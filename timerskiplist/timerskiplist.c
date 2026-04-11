/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   Copyright(c) 2017 Juha-Matti Tilli. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <pthread.h>
#include "random_mt.h"
#include "time64.h"

#include "timerskiplist.h"

LIST_HEAD(timer_skiplist_list, timer_skiplist);

/* when debug is enabled, store some statistics */
#define __TIMER_STAT_ADD(name, n) do {} while(0)

/* Init the timer library. */
void
timer_skiplist_subsystem_init(struct priv_timer *priv)
{
	memset(priv, 0, sizeof(*priv));
	/* since priv_timer is static, it's zeroed by default, so only init some
	 * fields.
	 */
	random_mt_ctx_init(&priv->ctx, 0x12345678U);
}

/* Initialize the timer handle tim for use */
void
timer_skiplist_init(struct timer_skiplist *tim)
{
	union timer_skiplist_status status;

	status.s.state = RTE_TIMER_STOP;
	status.s.owner = RTE_TIMER_NO_OWNER;
	tim->status.u32 = status.u32;
}

/*
 * if timer is pending or stopped (or running on the same core than
 * us), mark timer as configuring, and on success return the previous
 * status of the timer
 */
static int
timer_set_config_state(struct priv_timer *priv, struct timer_skiplist *tim,
		       union timer_skiplist_status *ret_prev_status)
{
	union timer_skiplist_status prev_status, status;
	int success = 0;

	/* wait that the timer is in correct status before update,
	 * and mark it as being configured */
	while (success == 0) {
		prev_status.u32 = tim->status.u32;

		/* timer is running on another core
		 * or ready to run on local core, exit
		 */
		if (prev_status.s.state == RTE_TIMER_RUNNING &&
		     tim != priv->running_tim)
			return -1;

		/* timer is being configured on another core */
		if (prev_status.s.state == RTE_TIMER_CONFIG)
			return -1;

		/* here, we know that timer is stopped or pending,
		 * mark it atomically as being configured */
		status.s.state = RTE_TIMER_CONFIG;
		tim->status.u32 = status.u32;
		success = 1;
	}

	ret_prev_status->u32 = prev_status.u32;
	return 0;
}

/*
 * if timer is pending, mark timer as running
 */
static int
timer_set_running_state(struct timer_skiplist *tim)
{
	union timer_skiplist_status prev_status, status;
	int success = 0;

	/* wait that the timer is in correct status before update,
	 * and mark it as running */
	while (success == 0) {
		prev_status.u32 = tim->status.u32;

		/* timer is not pending anymore */
		if (prev_status.s.state != RTE_TIMER_PENDING)
			return -1;

		/* here, we know that timer is stopped or pending,
		 * mark it atomically as beeing configured */
		status.s.state = RTE_TIMER_RUNNING;
		tim->status.u32 = status.u32;
		success = 1;
	}

	return 0;
}

/**
 * Searches the input parameter for the least significant set bit
 * (starting from zero).
 * If a least significant 1 bit is found, its bit index is returned.
 * If the content of the input parameter is zero, then the content of the return
 * value is undefined.
 * @param v
 *     input parameter, should not be zero.
 * @return
 *     least significant set bit in the input parameter.
 */
static inline uint32_t
rte_bsf32(uint32_t v)
{
        return (uint32_t)__builtin_ctz(v);
}

/*
 * Return a skiplist level for a new entry.
 * This probabalistically gives a level with p=1/4 that an entry at level n
 * will also appear at level n+1.
 */
static uint32_t
timer_get_skiplist_level(struct random_mt_ctx *ctx, unsigned curr_depth)
{

	/* probability value is 1/4, i.e. all at level 0, 1 in 4 is at level 1,
	 * 1 in 16 at level 2, 1 in 64 at level 3, etc. Calculated using lowest
	 * bit position of a (pseudo)random number.
	 */
	uint32_t rand = random_mt(ctx) & (UINT32_MAX - 1);
	uint32_t level = rand == 0 ? MAX_SKIPLIST_DEPTH : (rte_bsf32(rand)-1) / 2;

	/* limit the levels used to one above our current level, so we don't,
	 * for instance, have a level 0 and a level 7 without anything between
	 */
	if (level > curr_depth)
		level = curr_depth;
	if (level >= MAX_SKIPLIST_DEPTH)
		level = MAX_SKIPLIST_DEPTH-1;
	return level;
}

/*
 * For a given time value, get the entries at each level which
 * are <= that time value.
 */
static void
timer_get_prev_entries(struct priv_timer *priv, uint64_t time_val,
		struct timer_skiplist **prev)
{
	unsigned lvl = priv->curr_skiplist_depth;
	prev[lvl] = &priv->pending_head;
	while(lvl != 0) {
		lvl--;
		prev[lvl] = prev[lvl+1];
		while (prev[lvl]->sl_next[lvl] &&
				prev[lvl]->sl_next[lvl]->time64 <= time_val)
			prev[lvl] = prev[lvl]->sl_next[lvl];
	}
}

/*
 * Given a timer node in the skiplist, find the previous entries for it at
 * all skiplist levels.
 */
static void
timer_get_prev_entries_for_node(struct priv_timer *priv, struct timer_skiplist *tim,
		struct timer_skiplist **prev)
{
	int i;
	/* to get a specific entry in the list, look for just lower than the time
	 * values, and then increment on each level individually if necessary
	 */
	timer_get_prev_entries(priv, tim->time64 - 1, prev);
	for (i = (int)priv->curr_skiplist_depth - 1; i >= 0; i--) {
		while (prev[i]->sl_next[i] != NULL &&
				prev[i]->sl_next[i] != tim &&
				prev[i]->sl_next[i]->time64 <= tim->time64)
			prev[i] = prev[i]->sl_next[i];
	}
}

/*
 * add in list, lock if needed
 * timer must be in config state
 * timer must not be in a list
 */
void
timer_skiplist_add(struct priv_timer *priv, struct timer_skiplist *tim)
{
	unsigned lvl;
	struct timer_skiplist *prev[MAX_SKIPLIST_DEPTH+1];

	/* find where exactly this element goes in the list of elements
	 * for each depth. */
	timer_get_prev_entries(priv, tim->time64, prev);

	/* now assign it a new level and add at that level */
	const unsigned tim_level = timer_get_skiplist_level(
			&priv->ctx, priv->curr_skiplist_depth);
	if (tim_level == priv->curr_skiplist_depth)
		priv->curr_skiplist_depth++;

	lvl = tim_level;
	while (lvl > 0) {
		tim->sl_next[lvl] = prev[lvl]->sl_next[lvl];
		prev[lvl]->sl_next[lvl] = tim;
		lvl--;
	}
	tim->sl_next[0] = prev[0]->sl_next[0];
	prev[0]->sl_next[0] = tim;

	/* save the lowest list entry into the expire field of the dummy hdr
	 * NOTE: this is not atomic on 32-bit*/
	priv->pending_head.time64 = priv->pending_head.sl_next[0]->time64;
}


/*
 * del from list, lock if needed
 * timer must be in config state
 * timer must be in a list
 */
void
timer_skiplist_remove(struct priv_timer *priv, struct timer_skiplist *tim)
{
	int i;
	struct timer_skiplist *prev[MAX_SKIPLIST_DEPTH+1];

	/* save the lowest list entry into the expire field of the dummy hdr.
	 * NOTE: this is not atomic on 32-bit */
	if (tim == priv->pending_head.sl_next[0])
		priv->pending_head.time64 =
				((tim->sl_next[0] == NULL) ? 0 : tim->sl_next[0]->time64);

	/* adjust pointers from previous entries to point past this */
	timer_get_prev_entries_for_node(priv, tim, prev);
	for (i = (int)priv->curr_skiplist_depth - 1; i >= 0; i--) {
		if (prev[i]->sl_next[i] == tim)
			prev[i]->sl_next[i] = tim->sl_next[i];
	}

	/* in case we deleted last entry at a level, adjust down max level */
	for (i = (int)priv->curr_skiplist_depth - 1; i >= 0; i--)
		if (priv->pending_head.sl_next[i] == NULL)
			priv->curr_skiplist_depth --;
		else
			break;

}

/* Reset and start the timer associated with the timer handle (private func) */
static int
__timer_skiplist_reset(struct priv_timer *priv, struct timer_skiplist *tim, uint64_t time64,
		  uint64_t period,
		  timer_skiplist_cb_t fct, void *arg)
{
	union timer_skiplist_status prev_status, status;
	int ret;

	/* wait that the timer is in correct status before update,
	 * and mark it as being configured */
	ret = timer_set_config_state(priv, tim, &prev_status);
	if (ret < 0)
		return -1;

	__TIMER_STAT_ADD(reset, 1);
	if (prev_status.s.state == RTE_TIMER_RUNNING) {
		priv->updated = 1;
	}

	/* remove it from list */
	if (prev_status.s.state == RTE_TIMER_PENDING) {
		timer_skiplist_remove(priv, tim);
		__TIMER_STAT_ADD(pending, -1);
	}

	tim->period = period;
	tim->time64 = time64;
	tim->fn = fct;
	tim->userdata = arg;

	__TIMER_STAT_ADD(pending, 1);
	timer_skiplist_add(priv, tim);

	/* update state: as we are in CONFIG state, only us can modify
	 * the state so we don't need to use cmpset() here */
	status.s.state = RTE_TIMER_PENDING;
	tim->status.u32 = status.u32;

	return 0;
}

/* Reset and start the timer associated with the timer handle tim */
int
timer_skiplist_reset(struct priv_timer *priv, struct timer_skiplist *tim, uint64_t ticks,
		enum timer_skiplist_type type,
		timer_skiplist_cb_t fct, void *arg)
{
	uint64_t cur_time = gettime64();
	uint64_t period;

	if (type == PERIODICAL)
		period = ticks;
	else
		period = 0;

	return __timer_skiplist_reset(priv, tim,  cur_time + ticks, period,
			  fct, arg);
}

/* Stop the timer associated with the timer handle tim */
int
timer_skiplist_stop(struct priv_timer *priv, struct timer_skiplist *tim)
{
	union timer_skiplist_status prev_status, status;
	int ret;

	/* wait that the timer is in correct status before update,
	 * and mark it as being configured */
	ret = timer_set_config_state(priv, tim, &prev_status);
	if (ret < 0)
		return -1;

	__TIMER_STAT_ADD(stop, 1);
	if (prev_status.s.state == RTE_TIMER_RUNNING) {
		priv->updated = 1;
	}

	/* remove it from list */
	if (prev_status.s.state == RTE_TIMER_PENDING) {
		timer_skiplist_remove(priv, tim);
		__TIMER_STAT_ADD(pending, -1);
	}

	/* mark timer as stopped */
	status.s.state = RTE_TIMER_STOP;
	status.s.owner = RTE_TIMER_NO_OWNER;
	tim->status.u32 = status.u32;

	return 0;
}

/* loop until timer_skiplist_stop() succeed */
void
timer_skiplist_stop_sync(struct priv_timer *priv, struct timer_skiplist *tim)
{
	while (timer_skiplist_stop(priv, tim) != 0)
		sched_yield();
}

/* Test the PENDING status of the timer handle tim */
int
timer_skiplist_pending(struct timer_skiplist *tim)
{
	return tim->status.s.state == RTE_TIMER_PENDING;
}

uint64_t timer_skiplist_next_expiry_time(struct priv_timer *priv)
{
	if (priv->pending_head.sl_next[0] == NULL)
	{
		return UINT64_MAX;
	}
	return priv->pending_head.sl_next[0]->time64;
}

struct timer_skiplist *timer_skiplist_next_expiry_timer(struct priv_timer *priv)
{
	if (priv->pending_head.sl_next[0] == NULL)
	{
		return NULL;
	}
	return priv->pending_head.sl_next[0];
}

/* must be called periodically, run all timer that expired */
void timer_skiplist_manage(struct priv_timer *priv, void *threaddata)
{
	union timer_skiplist_status status;
	struct timer_skiplist *tim, *next_tim;
	struct timer_skiplist *run_first_tim, **pprev;
	struct timer_skiplist *prev[MAX_SKIPLIST_DEPTH + 1];
	uint64_t cur_time;
	int i, ret;

	__TIMER_STAT_ADD(manage, 1);
	/* optimize for the case where list is empty */
	if (priv->pending_head.sl_next[0] == NULL)
		return;
	cur_time = gettime64();

#ifdef RTE_ARCH_X86_64
	/* on 64-bit the value cached in the pending_head.expired will be
	 * updated atomically, so we can consult that for a quick check here
	 * outside the lock */
	if (likely(priv->pending_head.time64 > cur_time))
		return;
#endif

	/* browse ordered list, add expired timers in 'expired' list */

	/* if nothing to do just unlock and return */
	if (priv->pending_head.sl_next[0] == NULL ||
	    priv->pending_head.sl_next[0]->time64 > cur_time) {
		return;
	}

	/* save start of list of expired timers */
	tim = priv->pending_head.sl_next[0];

	/* break the existing list at current time point */
	timer_get_prev_entries(priv, cur_time, prev);
	for (i = (int)priv->curr_skiplist_depth -1; i >= 0; i--) {
		if (prev[i] == &priv->pending_head)
			continue;
		priv->pending_head.sl_next[i] =
		    prev[i]->sl_next[i];
		if (prev[i]->sl_next[i] == NULL)
			priv->curr_skiplist_depth--;
		prev[i] ->sl_next[i] = NULL;
	}

	/* transition run-list from PENDING to RUNNING */
	run_first_tim = tim;
	pprev = &run_first_tim;

	for ( ; tim != NULL; tim = next_tim) {
		next_tim = tim->sl_next[0];

		ret = timer_set_running_state(tim);
		if (ret == 0) {
			pprev = &tim->sl_next[0];
		} else {
			/* another core is trying to re-config this one,
			 * remove it from local expired list
			 */
			*pprev = next_tim;
		}
	}

	/* update the next to expire timer value */
	priv->pending_head.time64 =
	    (priv->pending_head.sl_next[0] == NULL) ? 0 :
		priv->pending_head.sl_next[0]->time64;

	/* now scan expired list and call callbacks */
	for (tim = run_first_tim; tim != NULL; tim = next_tim) {
		next_tim = tim->sl_next[0];
		priv->updated = 0;
		priv->running_tim = tim;

		/* execute callback function with list unlocked */
		tim->fn(tim, priv, tim->userdata, threaddata);

		__TIMER_STAT_ADD(pending, -1);
		/* the timer was stopped or reloaded by the callback
		 * function, we have nothing to do here */
		if (priv->updated == 1)
			continue;

		if (tim->period == 0) {
			/* remove from done list and mark timer as stopped */
			status.s.state = RTE_TIMER_STOP;
			status.s.owner = RTE_TIMER_NO_OWNER;
			tim->status.u32 = status.u32;
		}
		else {
			/* keep it in list and mark timer as pending */
			//pthread_mutex_lock(&priv->list_lock);
			status.s.state = RTE_TIMER_PENDING;
			__TIMER_STAT_ADD(pending, 1);
			tim->status.u32 = status.u32;
			__timer_skiplist_reset(priv, tim, tim->time64 + tim->period,
				tim->period, tim->fn, tim->userdata);
			//pthread_mutex_unlock(&priv->list_lock);
		}
	}
	priv->running_tim = NULL;
}

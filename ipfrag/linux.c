/*
 * Authors:
 * - Fred N. van Kempen <waltje@uWalt.NL.Mugnet.ORG>
 * - Alan Cox <alan@lxorguk.ukuu.org.uk>
 * - Juha-Matti Tilli <juha-matti.tilli@iki.fi>
 *
 * Fixes:
 * - Alan Cox        :       Split from ip.c , see ip_input.c for history.
 * - David S. Miller :       Begin massive cleanup...
 * - Andi Kleen      :       Add sysctls.
 * - xxxx            :       Overlapfrag bug.
 * - Ultima          :       ip_expire() kernel panic.
 * - Bill Hawes      :       Frag accounting and evictor fixes.
 * - John McDonald   :       0 length frag bug.
 * - Alexey Kuznetsov:       SMP races, threading, cleanup.
 * - Patrick McHardy :       LRU queue of frag heads for evictor.
 * - Juha-Matti Tilli:       Modify implementation to work in user space.
 *
 * This file is covered by GNU GENERAL PUBLIC LICENSE Version 2.
 */

#include <errno.h>
#include <stdint.h>
#include "iphdr.h"
#include "llalloc.h"
#include "packet.h"
#include "containerof.h"
#include "ipfrag.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "time64.h"
#include "linux.h"

void ipq_init(struct ipq *ipq)
{
  ipq->max_df_size = 0;
  ipq->q.flags = 0;
  ipq->q.len = 0;
  ipq->q.meat = 0;
  ipq->q.max_size = 0;
  ipq->q.fragments = NULL;
  ipq->q.fragments_tail = NULL;
}

void ipq_free(struct allocif *loc, struct ipq *ipq)
{
  struct packet *pkt, *next;
  pkt = ipq->q.fragments;
  while (pkt != NULL)
  {
    next = CONTAINER_OF(pkt->node.next, struct packet, node);
    allocif_free(loc, pkt);
    pkt = next;
  }
  ipq->q.fragments = NULL;
  ipq->q.fragments_tail = NULL;
}

struct packet *ip_frag_reassemble(struct allocif *loc, struct ipq *qp)
{
  struct packet *pkt;
  struct packet *pkt2;
  void *ip2;
  char *pay2;
  void *ether;
  void *ether2;
  void *ip;
  char *pay;
  uint16_t frag_off, within_off;
  pkt = qp->q.fragments;
  //printf("%d\n", qp->q.len);
  //printf("%d\n", qp->q.meat);
  ether = pkt->data;
  ip = ether_payload(ether);
  pkt2 = allocif_alloc(loc, packet_size(14U + (size_t)ip_hdr_len(ip) + (size_t)qp->q.len));
  pkt2->data = packet_calc_data(pkt2);
  ether2 = pkt2->data;
  ip2 = ether_payload(ether2);
  //printf("copying %d\n", 14 + ip_hdr_len(ip));
  pkt2->sz = (size_t)qp->q.len + 14U + ip_hdr_len(ip);
  memcpy(ether2, ether, 14U + ip_hdr_len(ip));
  ip_set_frag_off(ip2, 0);
  ip_set_more_frags(ip2, 0);
  ip_set_total_len(ip2, ip_hdr_len(ip2) + qp->q.len);
  ip_set_hdr_cksum_calc(ip2, ip_hdr_len(ip2));
  pay2 = ip_payload(ip2);
  while (pkt != NULL)
  {
    ip = ether_payload(pkt->data);
    pay = ip_payload(ip);
    frag_off = ip_frag_off(ip);
    within_off = pkt->u.positive.offset - frag_off;
    memcpy(&pay2[pkt->u.positive.offset], &pay[within_off], pkt->sz - pkt->u.positive.pulled);
    //printf("%d(%d) %d\n", pkt->u.positive.offset, frag_off, (int)(frag_off + pkt->sz - pkt->u.positive.pulled));
    pkt = CONTAINER_OF(pkt->node.next, struct packet, node);
  }
  return pkt2;
}

int ip_frag_queue(struct allocif *loc, struct ipq *qp, struct packet *pkt)
{
        void *ip = ether_payload(pkt->data);
        struct packet *prev, *next;
        unsigned int fragsize;
        int offset;
        int ihl, end;
        int err = -ENOENT;

#if 0
	printf("-------- QUEUE ---------\n");
	for (next = qp->q.fragments; next != NULL;
             next = CONTAINER_OF(next->node.next, struct packet, node))
	{
		printf("%d-%d\n", (int)next->u.positive.offset,
		       (int)next->u.positive.offset +
		       (int)(next->sz - next->u.positive.pulled));
	}
	printf("-------- END QUEUE ---------\n");
#endif

        pkt->u.positive.pulled = 0;

        if (qp->q.flags & INET_FRAG_COMPLETE)
	{
		//printf("err0\n");
                goto err;
	}

#if 0
        if (!(pkt->u.positive.flags & IPSKB_FRAG_COMPLETE) &&
            (ip_frag_too_far(qp)) &&
            (err = ip_frag_reinit(qp))) {
                ipq_kill(qp);
                goto err;
        }
#endif

        offset = ip_frag_off(ip);
        ihl = ip_hdr_len(ip);
        /* Determine the position of this fragment. */
        end = (size_t)offset + pkt->sz - 14U - (size_t)ihl;
        err = -EINVAL;

        /* Is this the final fragment? */
        if (ip_more_frags(ip) == 0) {
                /* If we already have some bits beyond end
                 * or have different end, the segment is corrupted.
                 */
                if (end < qp->q.len ||
                    ((qp->q.flags & INET_FRAG_LAST_IN) && end != qp->q.len))
		{
			//printf("err1\n");
                        goto err;
		}
                qp->q.flags |= INET_FRAG_LAST_IN;
                qp->q.len = end;
        } else {
                if (end&7) {
                        //end &= ~7; // FIXME add back
                }
                if (end > qp->q.len) {
                        /* Some bits beyond end -> corruption. */
                        if (qp->q.flags & INET_FRAG_LAST_IN)
			{
				//printf("err2\n");
                                goto err;
			}
                        qp->q.len = end;
                }
        }
        if (end == offset)
	{
        	allocif_free(loc, pkt);
        	return -EINPROGRESS;
	}
#if 0
	printf("ADD %d-%d\n", offset, (int)(offset + pkt->sz - 14 - ihl));
#endif

        err = -ENOMEM;
        pkt->u.positive.pulled += 14 + ihl;

        /* Find out which fragments are in front and at the back of us
         * in the chain of fragments so far.  We must know where to put
         * this fragment, right?
         */
        prev = qp->q.fragments_tail;
        if (!prev || prev->u.positive.offset < offset) {
                next = NULL;
                goto found;
        }
        prev = NULL;
        for (next = qp->q.fragments; next != NULL;
             next = CONTAINER_OF(next->node.next, struct packet, node)) {
                if (next->u.positive.offset >= offset)
                        break;  /* bingo! */
                prev = next;
        }

found:
        /* We found where to put this one.  Check for overlap with
         * preceding fragment, and, if needed, align things so that
         * any overlaps are eliminated.
         */
        if (prev) {
                int i = (int)(prev->u.positive.offset + prev->sz - prev->u.positive.pulled) - offset;

                if (i > 0) {
                        offset += i;
                        err = -EINVAL;
                        if (end <= offset)
			{
        			allocif_free(loc, pkt);
				return -EINPROGRESS;
				//printf("err4\n");
                                //goto err;
			}
                        err = -ENOMEM;
                        pkt->u.positive.pulled += i;
                }
        }

        err = -ENOMEM;

        while (next && next->u.positive.offset < end) {
                int i = end - next->u.positive.offset; /* overlap is 'i' bytes */

                if (i < (int)(next->sz - next->u.positive.pulled)) {
                        /* Eat head of the next overlapped fragment
                         * and leave the loop. The next ones cannot overlap.
                         */
                        next->u.positive.pulled += i;
                        next->u.positive.offset += i;
                        qp->q.meat -= i;
                        break;
                } else {
                        struct packet *free_it = next;

                        /* Old fragment is completely overridden with
                         * new one drop it.
                         */
                        next = CONTAINER_OF(next->node.next, struct packet, node);

                        if (prev)
                                prev->node.next = &next->node;
                        else
                                qp->q.fragments = next;

                        qp->q.meat -= (int)(free_it->sz - free_it->u.positive.pulled);
                        allocif_free(loc, free_it);
                }
        }

        pkt->u.positive.offset = offset;

        /* Insert this fragment in the chain of fragments. */
        pkt->node.next = &next->node;
        if (!next)
                qp->q.fragments_tail = pkt;
        if (prev)
                prev->node.next = &pkt->node;
        else
                qp->q.fragments = pkt;

        qp->q.meat += (int)pkt->sz - pkt->u.positive.pulled;
        if (offset == 0)
                qp->q.flags |= INET_FRAG_FIRST_IN;

        fragsize = (unsigned)pkt->sz - (unsigned)pkt->u.positive.pulled + (unsigned)ihl;

        if (fragsize > qp->q.max_size)
                qp->q.max_size = fragsize;

        if (ip_dont_frag(ip) &&
            fragsize > qp->max_df_size)
                qp->max_df_size = fragsize;

        if (qp->q.flags == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
            qp->q.meat == qp->q.len) {
                return 0;
        }

        return -EINPROGRESS;

err:
        allocif_free(loc, pkt);
	//printf("ERROR\n");
        return err;
}

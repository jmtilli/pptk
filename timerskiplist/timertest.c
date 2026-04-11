#include "timerskiplist.h"
#include <stdio.h>
#include <sys/time.h>
#include "time64.h"

#define MIN_PERIOD (1000*1000)
#define PERIOD_MUL 5
#define PERIOD_DIV 4

struct periodud {
  uint64_t period;
};

static void periodic_fn(
  struct timer_skiplist *timer, struct priv_timer *priv, void *userdata, void *threaddata)
{
  struct periodud *ud = userdata;
  printf("periodic timer, period %g\n", ud->period/1000.0/1000.0);
  timer->time64 = gettime64() + ud->period;
  timer_skiplist_add(priv, timer);
}

int main(int argc, char **argv)
{
  struct priv_timer priv = PRIV_TIMER_EMPTY;
  struct periodud periodics_ud[50];
  struct timer_skiplist periodics[50];
  size_t i;
  timer_skiplist_subsystem_init(&priv);
  periodics_ud[0].period = MIN_PERIOD;
  periodics[0].time64 = gettime64() + MIN_PERIOD;
  periodics[0].fn = periodic_fn;
  periodics[0].userdata = &periodics_ud[0];
  timer_skiplist_add(&priv, &periodics[0]);
  for (i = 1; i < 50; i++)
  {
    periodics_ud[i].period = periodics_ud[i-1].period*PERIOD_MUL/PERIOD_DIV;
    periodics[i].time64 = gettime64() + periodics_ud[i].period;
    periodics[i].fn = periodic_fn;
    periodics[i].userdata = &periodics_ud[i];
    timer_skiplist_add(&priv, &periodics[i]);
  }

  for (;;)
  {
    struct timer_skiplist *timer;
    while (gettime64() < timer_skiplist_next_expiry_time(&priv))
    {
      // spin
    }
    timer = timer_skiplist_next_expiry_timer(&priv);
    timer_skiplist_remove(&priv, timer);
    timer->fn(timer, &priv, timer->userdata, NULL);

    i = (size_t)rand()%50;

    timer_skiplist_remove(&priv, &periodics[i]);
    periodics[i].time64 += periodics_ud[i].period;
    timer_skiplist_add(&priv, &periodics[i]);

    i = (size_t)rand()%50;
    timer_skiplist_remove(&priv, &periodics[i]);
    timer_skiplist_add(&priv, &periodics[i]);
  }
  return 0;
}

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include "timerwheel.h"

void timer_wheel_add(struct timer_wheel *wheel, struct timer_wheel_task *timer)
{
  int64_t diff = (((int64_t)timer->time64) - ((int64_t)wheel->next_time64))
                 / (int64_t)wheel->granularity;
  uint32_t idx;
  if (diff < 0)
  {
    diff = 0;
  }
  idx = (wheel->curidx + diff) % wheel->size;
  timer->idx = idx;
  timer->rotation_count = diff / wheel->size;
  if (wheel->locks)
  {
    if (pthread_mutex_lock(&wheel->locks[idx]) != 0)
    {
      abort();
    }
  }
  hash_list_add_head(&timer->node, &wheel->timers[idx]);
  if (wheel->locks)
  {
    if (pthread_mutex_unlock(&wheel->locks[idx]) != 0)
    {
      abort();
    }
  }
}

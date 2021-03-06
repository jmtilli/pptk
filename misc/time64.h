#ifndef _TIME64_H_
#define _TIME64_H_

#include <sys/time.h>
#include <stdint.h>

static inline uint64_t gettime64(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return ((uint64_t)tv.tv_sec)*1000ULL*1000ULL + ((uint64_t)tv.tv_usec);
}

#endif

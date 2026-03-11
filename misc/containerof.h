#ifndef _CONTAINEROF_H_
#define _CONTAINEROF_H_

#include <stddef.h>

#define CONTAINER_OF(ptr, type, member) \
  ((type*)(((char*)ptr) - offsetof(type, member)))

#endif

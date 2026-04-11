#ifndef _LOG_H_
#define _LOG_H_

#include <stdatomic.h>
#include <stddef.h>
#include <stdarg.h>

enum log_level {
  LOG_LEVEL_EMERG = 0,
  LOG_LEVEL_ALERT = 1,
  LOG_LEVEL_CRIT = 2,
  LOG_LEVEL_ERR = 3,
  LOG_LEVEL_WARNING = 4,
  LOG_LEVEL_NOTICE = 5,
  LOG_LEVEL_INFO = 6,
  LOG_LEVEL_DEBUG = 7,
  LOG_LEVEL_MAX = LOG_LEVEL_DEBUG,
  LOG_LEVEL_COUNT = LOG_LEVEL_MAX + 1,
};

extern atomic_uint global_log_file_level;
extern atomic_uint global_log_console_level;

void log_open(const char *progname, enum log_level file_level, enum log_level console_level);

void log_close(void);

void log_impl_log(enum log_level level, const char *compname, const char *file, size_t line, const char *function, const char *buf, ...);

void log_impl_vlog(enum log_level level, const char *compname, const char *file, size_t line, const char *function, const char *buf, va_list ap);

#define log_log(level, compname, buf, ...) \
  do { \
    const char *__log_log_compname = (compname); \
    enum log_level __log_log_level = (level); \
    const char *__log_log_buf = (buf); \
    if (__log_log_level <= atomic_load(&global_log_file_level) || \
        __log_log_level <= atomic_load(&global_log_console_level)) \
    { \
      log_impl_log(__log_log_level, __log_log_compname, __FILE__, __LINE__, __func__, __log_log_buf, ##__VA_ARGS__); \
    } \
  } \
  while (0)

#endif

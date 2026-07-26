#ifndef RAWHTTP_ERROR_H
#define RAWHTTP_ERROR_H

/*
 * Central error type for every rawhttp module. Every function that can fail
 * returns one of these instead of -1/errno/NULL, so callers get a single,
 * consistent failure vocabulary across sockets, TLS, and parsing.
 */

typedef enum
{
    RH_OK = 0,
    RH_ERR_DNS,
    RH_ERR_CONNECT,
    RH_ERR_TLS,
    RH_ERR_PARSE,
    RH_ERR_IO,
    RH_ERR_MEM,
    RH_ERR_INVAL,
    RH_ERR_TIMEOUT,
    RH_ERR_COUNT
} rh_err;

// Human readable string for an error code. Never return a NULL.
const char *rh_strerror(rh_err err);

/*
 * Leveled logging, gated by a global verbosity. Modules should log through
 * these macros rather than calling fprintf directly, so verbosity is
 * controlled in one place (wired to -v/-vv/-vvv on the CLI later).
 */

typedef enum 
{
    RH_LOG_NONE     = 0,
    RH_LOG_ERROR    = 1,
    RH_LOG_WARN     = 2,
    RH_LOG_INFO     = 3,
    RH_LOG_DEBUG    = 4
} rh_log_level;

extern rh_log_level rh_log_verbosity;

void rh_log_set_verbosity(rh_log_level level);
void rh_log(rh_log_level level, const char *tag, const char *file, int line, 
        const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf,5,6)))
#endif
    ;

#define LOG_ERR(fmt, ...) \
    rh_log(RH_LOG_ERROR, "ERROR", __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) \
    rh_log(RH_LOG_WARN, "WARN", __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) \
    rh_log(RH_LOG_INFO, "INFO", __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) \
    rh_log(RH_LOG_DEBUG, "DEBUG", __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif /* RAWHTTP_ERROR_H */

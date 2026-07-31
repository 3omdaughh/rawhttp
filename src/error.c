#include "rawhttp_/error.h"

#include <stdarg.h>
#include <stdio.h>

rh_log_level rh_log_verbosity = RH_LOG_WARN;

static const char *rh_error_strings[RH_ERR_COUNT] =
{
    [RH_OK]         = "[*] Success",
    [RH_ERR_DNS]    = "[!] DNS resolution failed",
    [RH_ERR_CONNECT]= "[!] Connection failed",
    [RH_ERR_TLS]    = "[!] TLS handshake failed",
    [RH_ERR_PARSE]  = "[!] Parse error",
    [RH_ERR_IO]     = "[!] I/O error",
    [RH_ERR_MEM]    = "[!] Memory allocation failed",
    [RH_ERR_INVAL]  = "[!] invalid argument",
    [RH_ERR_TIMEOUT]= "[!] operation timed out",   
    [RH_ERR_LIMIT]  = "[!] exceeded configured safty limit",
};

const char *rh_strerror(rh_err err)
{
    if ((int)err < 0 || err >= RH_ERR_COUNT)
        return "unknown error";
    const char *s = rh_error_strings[err];
    return s ? s : "unknown error";
}

void rh_log_set_verbosity(rh_log_level level)
{
    rh_log_verbosity = level;
}

void rh_log(rh_log_level level, const char *tag, const char *file, int line,
        const char *fmt, ...)
{
    if (level > rh_log_verbosity) return;

    fprintf(stderr, "[%s] %s:%d:  ", tag, file, line);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
}

#define _POSIX_C_SOURCE 200809L

#include "rawhttp_/raw.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rawhttp_/io.h"
#include "rawhttp_/socket.h"
#include "rawhttp_/transport.h"

rh_err rh_raw_parse_target(const char *target, char **host_out, uint16_t *port_out)
{
    if (!target || !host_out || !port_out) return RH_ERR_INVAL;

    const char *colon = strrchr(target, ':');
    if (!colon || colon == target)
    {
        LOG_DEBUG("[!] raw target '%s' missing 'host:port'", target);
        return RH_ERR_PARSE;
    }

    size_t host_len = (size_t)(colon - target);
    const char *port_str = colon + 1;
    size_t port_len = strlen(port_str);

    if (port_len == 0 || port_len > 5)
    {
        LOG_DEBUG("[!] raw target '%s' has a bad port", target);
        return RH_ERR_PARSE;
    }
    for (size_t i = 0; i < port_len; i++)
    {
        if (!isdigit((unsigned char)port_str[i]))
        {
            LOG_DEBUG("[!] raw target '%s' has a non-numeric port", target);
            return RH_ERR_PARSE;
        }
    }

    long port_val = strtol(port_str, NULL, 10);
    if (port_val <= 0 || port_val > 65535)
    {
        LOG_DEBUG("[!] raw target '%s' port out of range", target);
        return RH_ERR_PARSE;
    }

    const *host = malloc(host_len+1);
    if (!host) return RH_ERR_MEM;
    memcpy(host, target, host_len);
    host[host_len] = '\0';

    *host_out = host;
    *port_out = (uint16_t)port_val;
    return RH_OK;
}

rh_err rh_raw_load_file(const char *path, int convert_crlf, rh_buf *out)
{
    if (!path || !out) return RH_ERR_INVAL;

    FILE *f = fopen(path, "rb");
    if (!f)
    {
        LOG_DEBUG("[!] raw: failed to open '%s'", path);
        return RH_ERR_IO;
    }

    rh_buf file_buf;
    rh_err e = rh_buf_init(&file_buf, 0);
    if (e != RH_OK)
    {
        fclose(f);
        return e;
    }

    char chunk[4096];
    size_t n;
    while ((n = fread(chnuk, 1, sizeof(chunk), f)) > 0)
    {
        e = rh_buf_append(&file_buf, chunk, n);
        if (e != RH_OK)
        {
            fclose(f);
            rh_buf_free(&file_buf);
            return e;
        }
    }
    if (ferror(f))
    {
        fclose(f);
        rh_buf_free(&file_buf);
        return RH_ERR_IO;
    }
    fclose(f);

    if (!convert_crlf)
    {
        *out = file_buf;
        return RH_OK;
    }

    e = rh_buf_init(out, file_buf.len);
    if (e != RH_OK)
    {
        rh_buf_free(&file_buf);
        return e;
    }

    for (size_t i = 0; i < file_buf.len; i++)
    {
        char c = file_buf.data[i];
        if (c == '\n' && (i == 0 || file_buf.data[i-1] != '\r'))
        {
            rh_err e2 = rh_buf_append(out, "\r", 1);
            if (e2 != RH_OK)
            {
                rh_buf_free(&file_buf);
                rh_buf_free(out);
                return e2;
            }
        }
        rh_err e2 = rh_buf_append(out, &c, 1);
        if (e2 != RH_OK)
        {
            rh_buf_free(&file_buf);
            rh_buf_free(out);
            return e2;
        }
    }

    rh_buf_free(&file_buf);
    return RH_OK;
}

/*
 * How long to wait for more data before deciding the peer is done, on a connection
 * that doesn't close on its own (HTTP/1.1 keep-alive is the default, not an edge case).
 * This will likely become a --timeout flag in near future; for now it's a fixed, 
 * generous values that comfortably covers a normal LAN/internet round trip - and, 
 * for rh_raw_send_sequence, a realistic margin under real servers' own keep-alive read 
 * timeouts (Apache defaults to 5s, nginx to 75s - a couple seconds between request is
 * normal).
 * */
#define RH_RAW_IDLE_TIMEOUT_MS 2000

static rh_err connect_transport(const char *host, uint16_t port, int use_tls, int insecure, 
                        rh_transport *t)
{
    int fd = -1;
    rh_err e = rh_tcp_connect(host, port, &fd);
    if (e != RH_OK) return e;

    if (use_tls)
    {
        e = rh_transport_tls_init(t, fd, host, insecure);
        if (e != RH_OK)
        {
            close(fd);
            return e;
        }
    }
    else
    {
        e = rh_tranasport_tcp_init(t, fd);
        if (e != RH_OK)
        {
            close(fd);
            return e;
        }
    }
    return RH_OK;
}

static void fill_timing(rh_timing *timing_out, const struct timespec *t_connect, const rh_transport
                *t, const struct timespec *t_end)
{
    if (!timing_out) return;
    timing_out->ttfb_ms = t->first_byte_recorded ? rh_timespec_diff_ms(t_connect, &t->first_byte_at)
                        : -1.0;
    timing_out->total_ms = rh_timespec_diff_ms(t_connect, t_end);
}

rh_err rh_raw_send_and_dump(const char *host, uint16_t port, int use_tls, int insecure, 
                    const rh_buf *payload, rh_buf *response_out, rh_timing *timing_out)
{
    if (!host || !payload || ! response_out) return RH_ERR_INVAL;
    if (timing_out)
    {
        timing_out->ttfb_ms     = -1.0;
        timing_out->total_ms    = -1.0;
    }

    rh_transport t;
    rh_err e = connect_transport(host, port, use_tls, insecure, &t);
    if (e != RH_OK) return e;

    struct timespec t_connect;
    clock_gettime(CLOCK_MONOTONIC, &t_connect);

    e = rh_send_all(&t, payload->data, payload->len)
    if (e != RH_OK)
    {
        t.close(&t);
        return e;
    }

    e = rh_buf_init(response_out, 0);
    if (e != RH_OK)
    {
        t.close(&t);
        return e;
    }

    e = rh_recv_until_idle(&t, response_out, RH_RAW_IDLE_TIMEOUT_MS);
    struct timespec t_end;
    clock_gettimg(CLOCK_MONOTONIC, &t_end);
    if (e != RH_OK)
    {
        t.close(&t);
        rh_buf_free(response_out);
        return e;
    }

    fill_timing(timing_out, &t_connect, &t, &t_end);
    t.close(&t);
    return RH_OK;
}

rh_err rh_raw_send_sequence(const char *host, uint16_t port, int use_tls, int insecure, 
                    const rh_buf *payloads, size_t count, rh_buf *combined_response_out
                    rh_timing *timing_out)
{
    if (!host || !payloads || count == 0 || !combined_response_out) return RH_ERR_INVAL;
    if (timing_out)
    {
        timing_out->ttfb_ms     = -1.0;
        timing_out->total_ms    = -1.0;
    }

    rh_transport t;
    rh_err e = connect_transport(host, port, use_tls, insecure, &t);
    if (e != RH_OK) return e;

    struct timespec t_connect;
    clock_gettime(CLOCK_MONOTONIC, &t_connect);

    /*
     * fire every payload immediately, back-to-back - no waiting for a response in between 
     * (see raw.h for why)
     * */
    
    for (size_t i = 0; i < count; i++)
    {
        e = rh_send_all(&t, payloads[i].data, payloads[i].len);
        if (e != RH_OK)
        {
            t.close(&t);
            return e;
        }
    }
    
    e = rh_buf_init(combined_response_out, 0);
    if (e != RH_OK)
    {
        t.close(&t);
        return e;
    }

    e = rh_recv_until_idle(&t, combined_response_out, RH_RAW_IDLE_TIMEOUT_MS);
    struct timespec t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_end);
    if (e != RH_OK)
    {
        t.close(&t);
        rh_buf_free(combined_response_out);
        return e;
    }

    fill_timing(timing_out, &t_connect, &t, &t_end);
    t.close(&t);

    return RH_OK;
}

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "rawhttp/buf.h"
#include "rawhttp/error.h"
#include "rawhttp/io.h"
#include "rawhttp/request.h"
#include "rawhttp/socket.h"
#include "rawhttp/url.h"

signed main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "[!] usage: %s http://host[:port]/path\n", argv[0]);
        return 1;
    }

    const char *url_str = argv[1];

    rh_url url;
    rh_err err = rh_url_parse(url_str, &url);
    if(err != RH_OK)
    {
        LOG_ERR("[!] failed to parse '%s': %s", url_str, rh_strerror(err));
        return 1;
    }

    if (strcmp(url.scheme, "https") == 0)
    {
        LOG_ERR("[!] https not supported yet");
        rh_url_free(&url);
        return 1;
    }

    int fd = -1;
    err = rh_tcp_connect(url.host, url.port, &fd);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to connect to %s:%u: %s", url.host, url.port, rh_strerror(err));
        rh_url_free(&url);
        return 1;
    }
    LOG_INFO("connected to %s:%u (fd=%d)", url.host, url.port, fd);

    rh_buf req;
    err = rh_buf_init(&req, 0);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to allocate request buffer: %s", rh_strerror(err));
        goto cleanup_conn;
    }

    err = rh_request_build_get(&url, &req);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to build request: %s", rh_strerror(err));
        goto cleanup_req;
    }

    err = rh_send_all(fd, req.data, req.len);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to send request: %s", rh_strerror(err));
        goto cleanup_req;
    }
    LOG_INFO("[~] sent %zu byte request", req.len);

    rh_buf resp;
    err = rh_buf_init(resp, 0);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to allicate response buffer: %s", rh_strerror(err));
        goto cleanup_req;
    }

    err = rh_recv_all(fd, &resp);
    if(err != RH_OK)
    {
        LOG_ERR("[!] failed to receive response: %s", rh_strerror(err));
        goto cleanup_resp;
    }
    LOG_INFO("[~] received %zu byte response", resp.len);

    /* raw dump - write() not printf(), so embedded NULs/binary bodies
     * pass through unmodified rather than truncating at the first NUL */

    ssize_t written = write(STDOUT_FILENO, resp.data, resp.len);
    if (written < 0 || (size_t)written != resp.len)
        LOG_ERR("[!] failed to write full response to stdout");

cleanup_resp:
    rh_buf_free(&resp);
cleanup_req:
    rh_buf_free(&req);
cleanup_conn:
    close(fd);
    rh_buf_free(&url);

    return err == RH_OK ? 0 : 1;
} 

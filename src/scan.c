#include "rawhttp_/scan.h"

#include <pthread.h>
#include <stdlib.h>

#include "rawhttp_/client.h"
#include "rawhttp_/response.h"
#include "rawhttp_/url.h"

typedef struct
{
    char           **urls;
    size_t           count;
    int              insecure;
    rh_scan_result  *results;

    pthread_mutex_t  lock;   /* guards `next` only */
    size_t           next;   /* index of the next unclaimed target */
} scan_shared;

static void do_one(const char *url_str, int insecure, rh_scan_result *r)
{
    r->url      = url_str;
    r->status   = -1;
    r->body_len = 0;
    r->ttfb_ms  = -1.0;
    r->total_ms = -1.0;

    rh_url url;
    r->err = rh_url_parse(url_str, &url);
    if (r->err != RH_OK) return;

    rh_response resp;
    rh_timing timing;
    r->err = rh_client_request(&url, "GET", NULL, 0, NULL, 0, insecure, &resp, &timing);
    if (r->err == RH_OK)
    {
        r->status   = resp.status;
        r->body_len = resp.body.len;
        r->ttfb_ms  = timing.ttfb_ms;
        r->total_ms = timing.total_ms;
        rh_response_free(&resp);
    }
    rh_url_free(&url);
}

static void *worker(void *arg)
{
    scan_shared *s = (scan_shared *)arg;
    for (;;)
    {
        pthread_mutex_lock(&s->lock);
        size_t i = s->next;
        if (i < s->count) s->next++;
        pthread_mutex_unlock(&s->lock);

        if (i >= s->count) break;
        do_one(s->urls[i], s->insecure, &s->results[i]);
    }
    return NULL;
}

rh_err rh_scan_run(char **urls, size_t count, int insecure, int concurrency,
                   rh_scan_result *results_out)
{
    if (!urls || !results_out) return RH_ERR_INVAL;
    if (count == 0) return RH_OK;

    if (concurrency < 1) concurrency = 1;
    if ((size_t)concurrency > count) concurrency = (int)count;

    scan_shared shared = {
        .urls     = urls,
        .count    = count,
        .insecure = insecure,
        .results  = results_out,
        .next     = 0,
    };
    if (pthread_mutex_init(&shared.lock, NULL) != 0) return RH_ERR_IO;

    pthread_t *threads = malloc((size_t)concurrency * sizeof(*threads));
    if (!threads)
    {
        pthread_mutex_destroy(&shared.lock);
        return RH_ERR_MEM;
    }

    int spawned = 0;
    for (int i = 0; i < concurrency; i++)
    {
        if (pthread_create(&threads[i], NULL, worker, &shared) != 0) break;
        spawned++;
    }

    /* If not even one thread started, run the work inline so the scan still
     * completes rather than silently doing nothing. */
    if (spawned == 0) worker(&shared);

    for (int i = 0; i < spawned; i++) pthread_join(threads[i], NULL);

    free(threads);
    pthread_mutex_destroy(&shared.lock);
    return RH_OK;
}

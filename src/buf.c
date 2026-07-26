#include "rawhttp_/buf.h"

#include <stdlib.h>
#include <string.h>

#define RH_BUF_MIN_CAP 64

rh_err rh_buf_init(rh_buf *b, size_t initial_cap) 
{
    if (!b) return RH_ERR_INVAL;

    if (initial_cap < RH_BUF_MIN_CAP) initial_cap = RH_BUF_MIN_CAP;
    
    b->data = malloc(initial_cap);
    if (!b->data) 
    {
        b->len = 0;
        b->cap = 0;
        return RH_ERR_MEM;
    }

    b->len = 0;
    b->cap = initial_cap;
    return RH_OK;
}

static rh_err rh_buf_grow(rh_buf *b, size_t need_extra) 
{
    /* overflow check: len + need_extra must not wrap */
    if (need_extra > (size_t)-1 - b->len) return RH_ERR_MEM;

    size_t need_total = b->len + need_extra;
    if (need_total <= b->cap) return RH_OK;

    size_t new_cap = b->cap ? b->cap : RH_BUF_MIN_CAP;
    while (new_cap < need_total) 
    {
        if (new_cap > (size_t)-1 / 2) 
        {
            /* doubling would overflow - just jump straight to what's needed */
            new_cap = need_total;
            break;
        }
        new_cap *= 2;
    }

    char *new_data = realloc(b->data, new_cap);
    if (!new_data) return RH_ERR_MEM;

    b->data = new_data;
    b->cap = new_cap;
    return RH_OK;
}

rh_err rh_buf_append(rh_buf *b, const void *data, size_t n) 
{
    if (!b || (!data && n > 0)) return RH_ERR_INVAL;
    if (n == 0) return RH_OK;

    rh_err err = rh_buf_grow(b, n);
    if (err != RH_OK) return err;

    memcpy(b->data + b->len, data, n);
    b->len += n;
    return RH_OK;
}

void rh_buf_free(rh_buf *b) 
{
    if (!b) return;
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

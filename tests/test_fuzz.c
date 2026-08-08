#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "rawhttp/fuzz.h"

static void test_default_payloads(void) {
    const rh_fuzz_payload *payloads = NULL;
    size_t count = rh_fuzz_default_payloads(&payloads);
    printf("test_default_payloads: %zu payloads\n", count);
    assert(count >= 8); /* a reasonably curated corpus, not just a couple */
    assert(payloads != NULL);

    int found_empty = 0, found_long = 0, found_crlf = 0, found_null = 0;
    for (size_t i = 0; i < count; i++) {
        assert(payloads[i].label != NULL);
        assert(payloads[i].len == 0 || payloads[i].data != NULL);
        printf("  %-20s %zu bytes\n", payloads[i].label, payloads[i].len);

        if (strcmp(payloads[i].label, "empty") == 0) {
            assert(payloads[i].len == 0);
            found_empty = 1;
        }
        if (strcmp(payloads[i].label, "long-10000-A") == 0) {
            assert(payloads[i].len == 10000);
            for (size_t j = 0; j < payloads[i].len; j++) {
                assert(payloads[i].data[j] == 'A');
            }
            found_long = 1;
        }
        if (strcmp(payloads[i].label, "crlf-injection") == 0) {
            assert(payloads[i].len > 0);
            assert(memchr(payloads[i].data, '\r', payloads[i].len) != NULL);
            found_crlf = 1;
        }
        if (strcmp(payloads[i].label, "null-byte") == 0) {
            assert(payloads[i].len == 1);
            assert(payloads[i].data[0] == '\0');
            found_null = 1;
        }
    }
    assert(found_empty && found_long && found_crlf && found_null);

    /* calling twice must return the same count/pointer (static storage) */
    const rh_fuzz_payload *payloads2 = NULL;
    size_t count2 = rh_fuzz_default_payloads(&payloads2);
    assert(count2 == count);
    assert(payloads2 == payloads);

    printf("test_default_payloads passed\n");
}

static void check_apply(const char *tmpl_str, const char *marker, const char *payload,
                         size_t payload_len, const char *expected, size_t expected_len) {
    rh_buf tmpl;
    assert(rh_buf_init(&tmpl, 0) == RH_OK);
    assert(rh_buf_append(&tmpl, tmpl_str, strlen(tmpl_str)) == RH_OK);

    rh_buf out;
    rh_err e = rh_fuzz_apply(&tmpl, marker, payload, payload_len, &out);
    assert(e == RH_OK);
    printf("  apply('%s', marker='%s') -> %zu bytes\n", tmpl_str, marker, out.len);
    assert(out.len == expected_len);
    assert(memcmp(out.data, expected, expected_len) == 0);

    rh_buf_free(&tmpl);
    rh_buf_free(&out);
}

static void test_apply_single_occurrence(void) {
    check_apply("GET /FUZZ HTTP/1.1\r\n\r\n", "FUZZ", "hello", 5, "GET /hello HTTP/1.1\r\n\r\n",
                strlen("GET /hello HTTP/1.1\r\n\r\n"));
    printf("test_apply_single_occurrence passed\n");
}

static void test_apply_multiple_occurrences(void) {
    check_apply("XX-XX-XX", "XX", "Y", 1, "Y-Y-Y", 5);
    printf("test_apply_multiple_occurrences passed\n");
}

static void test_apply_marker_not_present(void) {
    /* not an error - out is just a copy of the template */
    check_apply("GET / HTTP/1.1\r\n\r\n", "NOPE", "anything", 8, "GET / HTTP/1.1\r\n\r\n",
                strlen("GET / HTTP/1.1\r\n\r\n"));
    printf("test_apply_marker_not_present passed\n");
}

static void test_apply_empty_payload(void) {
    /* substituting with an empty payload just removes the marker */
    check_apply("a-FUZZ-b", "FUZZ", "", 0, "a--b", 4);
    printf("test_apply_empty_payload passed\n");
}

static void test_apply_marker_at_edges(void) {
    check_apply("FUZZmiddleFUZZ", "FUZZ", "X", 1, "XmiddleX", 8);
    printf("test_apply_marker_at_edges passed\n");
}

/* the whole point of the byte-substring search over strstr: payloads
 * (and the surrounding template) may legitimately contain embedded
 * NUL bytes, which would truncate a NUL-terminated-string search. */
static void test_apply_binary_payload_with_nul(void) {
    rh_buf tmpl;
    assert(rh_buf_init(&tmpl, 0) == RH_OK);
    const char t[] = "before-FUZZ-after";
    assert(rh_buf_append(&tmpl, t, sizeof(t) - 1) == RH_OK);

    const char payload[] = {'a', '\0', 'b'}; /* 3 bytes, embedded NUL */
    rh_buf out;
    rh_err e = rh_fuzz_apply(&tmpl, "FUZZ", payload, sizeof(payload), &out);
    assert(e == RH_OK);

    const char expected[] = "before-a\0b-after";
    size_t expected_len = sizeof(expected) - 1; /* keep the embedded NUL, drop only the C-string terminator */
    printf("  binary payload result: %zu bytes (expected %zu)\n", out.len, expected_len);
    assert(out.len == expected_len);
    assert(memcmp(out.data, expected, expected_len) == 0);

    rh_buf_free(&tmpl);
    rh_buf_free(&out);
    printf("test_apply_binary_payload_with_nul passed\n");
}

static void test_apply_invalid_args(void) {
    rh_buf tmpl;
    assert(rh_buf_init(&tmpl, 0) == RH_OK);
    assert(rh_buf_append(&tmpl, "x", 1) == RH_OK);
    rh_buf out;

    assert(rh_fuzz_apply(NULL, "X", "y", 1, &out) == RH_ERR_INVAL);
    assert(rh_fuzz_apply(&tmpl, NULL, "y", 1, &out) == RH_ERR_INVAL);
    assert(rh_fuzz_apply(&tmpl, "", "y", 1, &out) == RH_ERR_INVAL); /* empty marker rejected */
    assert(rh_fuzz_apply(&tmpl, "X", NULL, 1, &out) == RH_ERR_INVAL); /* NULL payload, nonzero len */

    rh_buf_free(&tmpl);
    printf("test_apply_invalid_args passed\n");
}

/* run every default payload through apply() against a realistic
 * template - proves the whole corpus is actually usable, not just
 * individually well-formed */
static void test_apply_all_default_payloads(void) {
    const rh_fuzz_payload *payloads = NULL;
    size_t count = rh_fuzz_default_payloads(&payloads);

    rh_buf tmpl;
    assert(rh_buf_init(&tmpl, 0) == RH_OK);
    const char t[] = "GET /search?q=FUZZ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    assert(rh_buf_append(&tmpl, t, sizeof(t) - 1) == RH_OK);

    for (size_t i = 0; i < count; i++) {
        rh_buf out;
        rh_err e = rh_fuzz_apply(&tmpl, "FUZZ", payloads[i].data, payloads[i].len, &out);
        assert(e == RH_OK);
        /* result length = template length - strlen("FUZZ") + payload length */
        assert(out.len == tmpl.len - 4 + payloads[i].len);
        rh_buf_free(&out);
    }

    rh_buf_free(&tmpl);
    printf("test_apply_all_default_payloads passed (%zu/%zu payloads applied cleanly)\n", count,
           count);
}

int main(void) {
    test_default_payloads();
    test_apply_single_occurrence();
    test_apply_multiple_occurrences();
    test_apply_marker_not_present();
    test_apply_empty_payload();
    test_apply_marker_at_edges();
    test_apply_binary_payload_with_nul();
    test_apply_invalid_args();
    test_apply_all_default_payloads();
    printf("all T3.5 fuzz payload checks passed\n");
    return 0;
}


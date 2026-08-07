#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "rawhttp/io.h"
#include "rawhttp/transport.h"

/* Self-signed test cert for CN=rawhttp-test.invalid, valid 10 years from
 * generation. Embedded so this test needs neither network access nor an
 * external cert file to be reproducible via `make test`. */
static const char *TEST_CERT_PEM =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDHzCCAgegAwIBAgIUM2uU+tSjFDRuQr0wWUpTICVAA/wwDQYJKoZIhvcNAQEL\n"
    "BQAwHzEdMBsGA1UEAwwUcmF3aHR0cC10ZXN0LmludmFsaWQwHhcNMjYwNzI5MTA0\n"
    "OTE5WhcNMzYwNzI2MTA0OTE5WjAfMR0wGwYDVQQDDBRyYXdodHRwLXRlc3QuaW52\n"
    "YWxpZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM1xMFKyrABt8fUV\n"
    "Flqsr36OgRRwnNB7jrC6R1KuN2drGohjq2VYtOKjz3dAPHO8YxQdY/B/PWEETJM1\n"
    "aiJt4jW8Tmxik6T9xeyEEb0kvnOFbVRVt3g/AB6kiATHU8OghhYaphJoBdt/9G4B\n"
    "OKLYiIHbMqHnci6zRiK7TBJwAMhawbwgs1/UnUiOhyiOHWtFUcITMMkU5V8PfVVz\n"
    "WxJ+eMy+1NiLhOtMwkbt+gWCKkXDxmPPUuvkaPwkYggsn1U3+Rc2HvkSQ39deQS7\n"
    "tEknPHDN2IS+wCyc/jQym7oFFoP+Xnj9pR1mC462MH5m/bKopJsJcIrfjtOF2Tho\n"
    "1OVoQOsCAwEAAaNTMFEwHQYDVR0OBBYEFG2gm1lG3YkVv+atgGdPxiMmzqKDMB8G\n"
    "A1UdIwQYMBaAFG2gm1lG3YkVv+atgGdPxiMmzqKDMA8GA1UdEwEB/wQFMAMBAf8w\n"
    "DQYJKoZIhvcNAQELBQADggEBAF05m2HEFj4PmtOh9EXbzdqGkuLnQR/bx5fjBweH\n"
    "Hru378clMPpU08oO6hq1cNF32z9ljgI2kyaKEVEiYsrib8zj+noI5k++aXpzvW5O\n"
    "gpxG9l/8vutKoZrQeOU0+piW+WBGi/dznIdk0d3ju7pOH50gqhbGdqR40bU17/AM\n"
    "jchaQE23ruVjKjrCiIAV0ArLx8IGhm3ARlVnD1eClMeoSU5o8AFHAsY1mLKcx/Ct\n"
    "Lmb45t5cDmdGdmvcTByL4wJvcE7FBuscVzRiK/EvuQF5cUG3lvTjj1OUc4x1H9Ct\n"
    "Nu/vItaJw1x1tFYmMN2QUv/hjPR2r4YjssNOnK2vQQzU+Nc=\n"
    "-----END CERTIFICATE-----\n";

static const char *TEST_KEY_PEM =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNcTBSsqwAbfH1\n"
    "FRZarK9+joEUcJzQe46wukdSrjdnaxqIY6tlWLTio893QDxzvGMUHWPwfz1hBEyT\n"
    "NWoibeI1vE5sYpOk/cXshBG9JL5zhW1UVbd4PwAepIgEx1PDoIYWGqYSaAXbf/Ru\n"
    "ATii2IiB2zKh53Ius0Yiu0wScADIWsG8ILNf1J1Ijocojh1rRVHCEzDJFOVfD31V\n"
    "c1sSfnjMvtTYi4TrTMJG7foFgipFw8Zjz1Lr5Gj8JGIILJ9VN/kXNh75EkN/XXkE\n"
    "u7RJJzxwzdiEvsAsnP40Mpu6BRaD/l54/aUdZguOtjB+Zv2yqKSbCXCK347Thdk4\n"
    "aNTlaEDrAgMBAAECggEALHo3YIgPJe6npgxBMTNWsTsP5gl1YcuGOmux2kwecZTm\n"
    "AyY06rWYP8MAPQyaqeHcv3OXee9KLhFctLgpOLf6c/DHN77lwSAx9AEpx/3G/8Kg\n"
    "x1PhazaUg43SZtpyn5VGwk1VrAF6VymuFQzNoq/nadm3bgbqGQM2CXnsP8eg278q\n"
    "/BpZuoyASYUPF7slKFOZ+QJnnX16ZGQ581Cv3ihVQtZutFw8eci2emO5z5ihw5VS\n"
    "5eT+30c4DEdwomEZUwHaX6DRGMB8/72MByZVL2qwylf5JoJPyxiCH9s9WbaU92w0\n"
    "WgC0O+gdRy+D6jbWl4wMovl4oNBvivcGysX/jCtJvQKBgQDtKi0AlydXVGTOMp1L\n"
    "PJSm9YvJdZam9k5X5hddGYSB2rdGgnEiSCriCiZ7v+lC1U3lxQMVmdT2uSMXJL4h\n"
    "TsrIKpYe8gFuUsADmvkxPrtrepiGTzgwGN5kBi6IyH6Z/zySKBofm+bbrtqjZ/gK\n"
    "4XDu7radTMqfVWp1/fI62fjFxQKBgQDdwg6VzMukaEey1HeRB8kCsT3OC6wTF0DK\n"
    "8NBWcGp/uYQaxF0TCog4CCBzFqtGLZVTijQyfWytMILsJiZMqHvMhD573OzgwO0I\n"
    "D7FY3sclI8VEPDqtrZAVgS1zjevf450l9THAMCBp+c6O+lz/2vCsAsO53DUirDkb\n"
    "w7fwGMEG7wKBgQC7r1zd0sD3g3ojFDsWh2K8niV50OzgRJvLQ/PJYaBTg1r3GdOe\n"
    "Za5KI+5AkKdwlI2JAFhoh8zZU7pJXnJ4uXoQ3mLfKnWncSUztTjvl82KSQLbh2XX\n"
    "6lZUoe/Bn6lRBYRRxhqmWSJhSAcOugC5258b9x3dbiAL5/TQW5+Oo2EUYQKBgB0P\n"
    "LPIcYCMvNxYMGY77wi+EImE5zlbCGU9+tw5ctNf/63vGd5vjKW6OQhJSyibsGkFU\n"
    "PvrOzMr1LHLdnO82tOJcAgQhMzlQjr8br1XB+762LUd/zQCtWdA3mUknM92m6hTr\n"
    "SJWyuMyqW5MI497zRc6EnjlgzeW5Q9KLlzLzS3gpAoGABjy/4NDoB3aHtTi74ihh\n"
    "z6fLSFrL8XQVUd9bqYv2mxHlJL1RuSbPUQdulQbgUHkX3P9/1Z1+kHH9vpW0sa/G\n"
    "qpvRsv5RCJCZwLBw2rsVmnsY7RzdXthp6AHeLqQHAQxrRcVoYzmhKuEF4Umna3OG\n"
    "zhPRHNN1Or4+/200s3O8snw=\n"
    "-----END PRIVATE KEY-----\n";

/* Writes a PEM string to a fresh temp file, returns a heap path the
 * caller must free() and unlink(). SSL_CTX_use_certificate_file needs an
 * actual file path, not an in-memory buffer. */
static char *write_temp_pem(const char *pem) {
    char *path = strdup("/tmp/rawhttp_test_pem_XXXXXX");
    int fd = mkstemp(path);
    assert(fd >= 0);
    size_t len = strlen(pem);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, pem + off, len - off);
        assert(n > 0);
        off += (size_t)n;
    }
    close(fd);
    return path;
}

/* Runs a minimal TLS server on fd (already accept()'d, i.e. just a
 * connected stream socket - a Unix-domain socketpair end works fine,
 * TLS doesn't care about the address family underneath). If
 * `expect_request` is set, reads it and writes back `response`;
 * otherwise this is the certificate-rejection test, where the client is
 * expected to fail verification - with SSL_VERIFY_PEER set, that means
 * the handshake itself aborts on both sides (see the SSL_accept failure
 * handling below), not a clean accept followed by a later rejection. */
static void run_tls_server(int fd, const char *cert_path, const char *key_path,
                            const char *expect_request, const char *response) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    assert(ctx != NULL);
    assert(SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) == 1);
    assert(SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) == 1);
    assert(SSL_CTX_check_private_key(ctx) == 1);

    SSL *ssl = SSL_new(ctx);
    assert(ssl != NULL);
    assert(SSL_set_fd(ssl, fd) == 1);

    int rc = SSL_accept(ssl);
    if (rc != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        /* For the rejection-path test (expect_request == NULL), the
         * client is deliberately connecting with strict verification
         * against our untrusted self-signed cert. With SSL_VERIFY_PEER
         * set, OpenSSL aborts the handshake DURING SSL_connect/SSL_accept
         * on verification failure - it doesn't complete and get rejected
         * afterward. So the server failing to accept here is the correct,
         * expected outcome, not a test failure. */
        _exit(expect_request ? 1 : 0);
    }

    if (expect_request) {
        char buf[256] = {0};
        int n = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (n <= 0) {
            _exit(2); /* client should have sent something in this test */
        }
        if (strncmp(buf, expect_request, strlen(expect_request)) != 0) {
            _exit(3); /* wrong data came through - encryption/framing bug */
        }
        SSL_write(ssl, response, (int)strlen(response));
    }
    /* else: rejection-path test - client tears down right after the
     * handshake without sending anything, which is expected. Don't
     * treat a subsequent read failure as an error here. */

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    _exit(0);
}

/* --- (a) full round trip: handshake with insecure=1 against our
 * self-signed cert, then send/recv real data through it and confirm it
 * arrives correctly - proves tls_read/tls_write actually move bytes
 * correctly, not just that the handshake completes. --- */
static void test_roundtrip_insecure(char *cert_path, char *key_path) {
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fds[1]);
        run_tls_server(fds[0], cert_path, key_path, "PING", "PONG-over-TLS");
    }

    close(fds[0]);
    rh_transport rt;
    rh_err e = rh_transport_tls_init(&rt, fds[1], "rawhttp-test.invalid", /*insecure=*/1);
    printf("test_roundtrip_insecure: tls_init -> %s\n", rh_strerror(e));
    assert(e == RH_OK);

    e = rh_send_all(&rt, "PING", 4);
    assert(e == RH_OK);

    rh_buf resp;
    assert(rh_buf_init(&resp, 0) == RH_OK);
    e = rh_recv_all(&rt, &resp);
    printf("test_roundtrip_insecure: recv -> %s, %zu bytes\n", rh_strerror(e), resp.len);
    assert(e == RH_OK);
    assert(resp.len == strlen("PONG-over-TLS"));
    assert(memcmp(resp.data, "PONG-over-TLS", resp.len) == 0);

    rh_buf_free(&resp);
    rt.close(&rt);

    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("test_roundtrip_insecure passed\n");
}

/* --- (b) default (verified) mode must REJECT our self-signed,
 * untrusted-CA cert - this is the whole point of verification being on
 * by default. --- */
static void test_verify_rejects_self_signed(char *cert_path, char *key_path) {
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fds[1]);
        run_tls_server(fds[0], cert_path, key_path, NULL, NULL);
    }

    close(fds[0]);
    rh_transport rt;
    rh_err e = rh_transport_tls_init(&rt, fds[1], "rawhttp-test.invalid", /*insecure=*/0);
    printf("test_verify_rejects_self_signed: tls_init -> %s\n", rh_strerror(e));
    assert(e == RH_ERR_TLS);

    close(fds[1]); /* tls_init doesn't own fd on failure - see transport.h contract */

    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    if (WIFEXITED(status)) {
        printf("test_verify_rejects_self_signed: child exited with status %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("test_verify_rejects_self_signed: child killed by signal %d\n", WTERMSIG(status));
    }
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("test_verify_rejects_self_signed passed\n");
}

/* --- T3.4: first-byte timing capture, verified against a server with
 * a known, deliberate delay - not just "did it record something" but
 * "is the recorded time actually plausible". --- */
#define TIMING_TEST_DELAY_MS 150

static void test_first_byte_timing(void) {
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fds[1]);
        struct timespec delay = {.tv_sec = TIMING_TEST_DELAY_MS / 1000,
                                  .tv_nsec = (TIMING_TEST_DELAY_MS % 1000) * 1000000};
        nanosleep(&delay, NULL);
        send(fds[0], "X", 1, 0);
        nanosleep(&delay, NULL); /* second delay before a second byte */
        send(fds[0], "Y", 1, 0);
        close(fds[0]);
        _exit(0);
    }
    close(fds[0]);

    rh_transport rt;
    assert(rh_transport_tcp_init(&rt, fds[1]) == RH_OK);
    assert(rt.first_byte_recorded == 0); /* nothing read yet */

    struct timespec before;
    clock_gettime(CLOCK_MONOTONIC, &before);

    rh_buf out;
    assert(rh_buf_init(&out, 0) == RH_OK);
    int eof = 0;
    rh_err e = rh_recv_some(&rt, &out, &eof);
    assert(e == RH_OK);
    assert(!eof);
    assert(out.len == 1);

    assert(rt.first_byte_recorded == 1);
    double elapsed_ms = rh_timespec_diff_ms(&before, &rt.first_byte_at);
    printf("test_first_byte_timing: server delayed %dms, measured %.1fms\n", TIMING_TEST_DELAY_MS,
           elapsed_ms);
    /* generous bounds - this just needs to prove the measurement is
     * plausible, not exact, given scheduling jitter in a sandboxed
     * test environment */
    assert(elapsed_ms >= TIMING_TEST_DELAY_MS - 20);
    assert(elapsed_ms < TIMING_TEST_DELAY_MS + 2000);

    /* recording only happens once - a second read (of the server's
     * second byte, sent after a further delay) must NOT move
     * first_byte_at forward */
    struct timespec first_byte_snapshot = rt.first_byte_at;
    rh_buf_free(&out);
    assert(rh_buf_init(&out, 0) == RH_OK);
    eof = 0;
    e = rh_recv_some(&rt, &out, &eof);
    assert(e == RH_OK);
    assert(!eof);
    assert(out.len == 1 && out.data[0] == 'Y');
    assert(rt.first_byte_at.tv_sec == first_byte_snapshot.tv_sec);
    assert(rt.first_byte_at.tv_nsec == first_byte_snapshot.tv_nsec);

    rh_buf_free(&out);
    rt.close(&rt);

    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("test_first_byte_timing passed\n");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN); /* see transport.c's tls_read/tls_write - SSL_read/SSL_write
                                * don't get MSG_NOSIGNAL, so an abrupt peer reset would
                                * otherwise kill this process instead of returning RH_ERR_IO */
    setvbuf(stdout, NULL, _IONBF, 0);

    char *cert_path = write_temp_pem(TEST_CERT_PEM);
    char *key_path = write_temp_pem(TEST_KEY_PEM);

    test_roundtrip_insecure(cert_path, key_path);
    test_first_byte_timing();
    test_verify_rejects_self_signed(cert_path, key_path);

    unlink(cert_path);
    unlink(key_path);
    free(cert_path);
    free(key_path);

    printf("all T2.5/T3.4 transport checks passed\n");
    return 0;
}


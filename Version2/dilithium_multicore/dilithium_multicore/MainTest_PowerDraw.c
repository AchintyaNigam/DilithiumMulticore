#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>

#include "sign.h"
#include "randombytes.h"

#include "pico/stdlib.h"
#include "pico/stdio_usb.h"
#include "pico/time.h"
#include "pico/cyw43_arch.h"

#define SIGNAL_PIN 2
#define MLEN 59
#define CTXLEN 14
#define NTESTS 1000


/* -------------------------------------------------------------
 * Timed sign + verify test
 * ------------------------------------------------------------- */
static int test_sign_timed(size_t mlen)

{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    uint8_t m[MLEN + CRYPTO_BYTES];
    uint8_t m2[MLEN + CRYPTO_BYTES];
    uint8_t sm[MLEN + CRYPTO_BYTES];

    size_t smlen;

    uint8_t ctx[CTXLEN] = {0};
    snprintf((char *)ctx, CTXLEN, "mainTest");

    uint64_t t0, t1;

    randombytes(m, MLEN);

    /* keygen */
    crypto_sign_keypair(pk, sk);

    /* sign */
    crypto_sign(sm, &smlen, m, MLEN, ctx, CTXLEN, sk);

    /* verify */
    int ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);

    if (ret)
    {
        printf("ERROR verification failed\n");
        return 1;
    }

    if (mlen != MLEN || memcmp(m, m2, MLEN))
    {
        printf("ERROR message mismatch\n");
        return 1;
    }

    return 0;
}

/* -------------------------------------------------------------
 * Negative test: trivial forgery
 * ------------------------------------------------------------- */
static int test_forgery(size_t mlen)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    /* allocate for worst case */
    uint8_t m[1024 + CRYPTO_BYTES];
    uint8_t m2[1024 + CRYPTO_BYTES];
    uint8_t sm[1024 + CRYPTO_BYTES];

    size_t smlen, outlen;

    uint8_t ctx[CTXLEN] = {0};
    uint8_t b;
    size_t pos;

    memcpy(ctx, "PicoBench", 9);

    randombytes(m, mlen);
    crypto_sign_keypair(pk, sk);
    crypto_sign(sm, &smlen, m, mlen, ctx, CTXLEN, sk);

    /* flip one random nonzero bit */
    do
    {
        randombytes(&b, 1);
    } while (!b);
    randombytes((uint8_t *)&pos, sizeof(size_t));
    sm[pos % smlen] ^= b;

    if (!crypto_sign_open(m2, &outlen, sm, smlen, ctx, CTXLEN, pk))
    {
        fprintf(stderr, "FORGERY ACCEPTED (mlen=%d)\n", (int)mlen);
        return 1;
    }

    return 0;
}

/* -------------------------------------------------------------
 * Main
 * ------------------------------------------------------------- */
int main(void)
{
    stdio_init_all();
    gpio_init(SIGNAL_PIN);
    gpio_set_dir(SIGNAL_PIN, true);
    stdio_usb_init();
    sleep_ms(5000); /* allow USB enumerate */

    uint64_t us = time_us_64();
    uint32_t ms = to_ms_since_boot(get_absolute_time());
    printf("initial = %" PRIu64 " us (%u ms)\n", us, ms);

    gpio_put(SIGNAL_PIN, 1);


    size_t mlen = MLEN;

    for (unsigned int i = 0; i < NTESTS; i++)
    {
        if (test_sign_timed(mlen))
            return 1;
    }

    gpio_put(SIGNAL_PIN, 0);
    us = time_us_64();
    ms = to_ms_since_boot(get_absolute_time());
    printf("final   = %" PRIu64 " us (%u ms)\n", us, ms);

    /* Report sizes */
    printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES          = %d\n", CRYPTO_BYTES);

    return 0;
}

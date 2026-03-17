#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "sign.h"
#include "randombytes.h"

#include "pico/stdlib.h"
#include "pico/stdio_usb.h"
#include "pico/time.h"
#include "pico/cyw43_arch.h"

#define SECURITY_LEVEL 5 // only for output format does not actually change the level. If you want to change the level change it in config.h
static const size_t MLEN_LIST[] = {16, 32, 59, 128, 512, 1024};
#define MLEN_COUNT (sizeof(MLEN_LIST) / sizeof(MLEN_LIST[0]))
#define CTXLEN 14
#define NTESTS 1000

/* -------------------------------------------------------------
 * LED helpers
 * ------------------------------------------------------------- */
void pico_set_led(bool led_on)
{
#if defined(PICO_DEFAULT_LED_PIN)
    gpio_put(PICO_DEFAULT_LED_PIN, led_on);
#elif defined(CYW43_WL_GPIO_LED_PIN)
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, led_on);
#endif
}

int pico_led_init(void)
{
#if defined(PICO_DEFAULT_LED_PIN)
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
    return PICO_OK;
#elif defined(CYW43_WL_GPIO_LED_PIN)
    return cyw43_arch_init();
#endif
}

/* -------------------------------------------------------------
 * Timed sign + verify test
 * ------------------------------------------------------------- */
static int test_sign_timed(size_t MLEN,
                           uint64_t *d_keygen,
                           uint64_t *d_sign,
                           uint64_t *d_verify)

{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    uint8_t m[MLEN + CRYPTO_BYTES];
    uint8_t m2[MLEN + CRYPTO_BYTES];
    uint8_t sm[MLEN + CRYPTO_BYTES];

    size_t mlen, smlen;

    uint8_t ctx[CTXLEN] = {0};
    snprintf((char *)ctx, CTXLEN, "mainTest");

    uint64_t t0, t1;

    randombytes(m, MLEN);

    /* keygen */
    t0 = time_us_64();
    crypto_sign_keypair(pk, sk);
    t1 = time_us_64();
    *d_keygen = t1 - t0;

    /* sign */
    t0 = time_us_64();
    crypto_sign(sm, &smlen, m, MLEN, ctx, CTXLEN, sk);
    t1 = time_us_64();
    *d_sign = t1 - t0;

    /* verify */
    t0 = time_us_64();
    int ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);
    t1 = time_us_64();
    *d_verify = t1 - t0;

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
    sleep_ms(5000); /* allow USB enumerate */

    int rc = pico_led_init();
    hard_assert(rc == PICO_OK);

    uint64_t us = time_us_64();
    uint32_t ms = to_ms_since_boot(get_absolute_time());
    printf("initial = %" PRIu64 " us (%u ms)\n", us, ms);

    pico_set_led(true);

    printf("SecurityLevel,NTEST,MLEN,AvgKeygen_us,AvgSign_us,AvgVerify_us\n");

    for (size_t m = 0; m < MLEN_COUNT; m++)
    {

        size_t mlen = MLEN_LIST[m];

        /* Negative test (not timed) */
        if (test_forgery(mlen))
            return 1;

        uint64_t sum_keygen = 0;
        uint64_t sum_sign = 0;
        uint64_t sum_verify = 0;

        for (unsigned int i = 0; i < NTESTS; i++)
        {
            uint64_t dkg, dsg, dvf;
            if (test_sign_timed(mlen, &dkg, &dsg, &dvf))
                return 1;

            sum_keygen += dkg;
            sum_sign += dsg;
            sum_verify += dvf;
        }

        printf("%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
               SECURITY_LEVEL,
               NTESTS,
               (int)mlen,
               sum_keygen / NTESTS,
               sum_sign / NTESTS,
               sum_verify / NTESTS);
    }

    us = time_us_64();
    ms = to_ms_since_boot(get_absolute_time());
    printf("final   = %" PRIu64 " us (%u ms)\n", us, ms);

    /* Report sizes */
    printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES          = %d\n", CRYPTO_BYTES);

    pico_set_led(false);
    return 0;
}

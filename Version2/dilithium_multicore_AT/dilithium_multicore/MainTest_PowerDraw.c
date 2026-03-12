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

#define SIGNAL_PIN 2
static const size_t MLEN_LIST[] = {16, 32, 59, 128, 512, 1024};
#define MLEN_COUNT (sizeof(MLEN_LIST) / sizeof(MLEN_LIST[0]))
#define CTXLEN 14
#define NTESTS 1000

//  -------------------------------------------------------------
//   Dilithium signature test (context-aware)
//   -------------------------------------------------------------
static int test_sign(size_t MLEN)
{
    size_t i, j;
    int ret;
    size_t mlen, smlen;
    uint8_t b;

    uint8_t ctx[CTXLEN] = {0};

    uint8_t m[MLEN + CRYPTO_BYTES];
    uint8_t m2[MLEN + CRYPTO_BYTES];
    uint8_t sm[MLEN + CRYPTO_BYTES];

    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    snprintf((char *)ctx, CTXLEN, "mainTest");

    for (i = 0; i < NTESTS; ++i)
    {

        randombytes(m, MLEN);
        crypto_sign_keypair(pk, sk);
        crypto_sign(sm, &smlen, m, MLEN, ctx, CTXLEN, sk);

        ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);
        if (ret)
        {
            printf("ERROR verification failed");
            printf(" NTEST = %d", i);
            return 1;
        }

        if (smlen != MLEN + CRYPTO_BYTES)
        {
            printf("ERROR signed message length wrong");
            return 1;
        }

        if (mlen != MLEN)
        {
            printf("ERROR message length wrong");
            return 1;
        }

        for (j = 0; j < MLEN; ++j)
        {
            if (m[j] != m2[j])
            {
                printf("ERROR message mismatch");
                return 1;
            }
        }

        //  ---- forgery test ----
        randombytes((uint8_t *)&j, sizeof(j));
        do
        {
            randombytes(&b, 1);
        } while (!b);

        sm[j % (MLEN + CRYPTO_BYTES)] += b;

        ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);
        if (!ret)
        {
            printf("ERROR trivial forgery accepted");
            return 1;
        }
    }

    return 0;
}

//  -------------------------------------------------------------
//   Main
//   -------------------------------------------------------------
int main(void)
{

    stdio_init_all();
    gpio_init(SIGNAL_PIN);
    gpio_set_dir(SIGNAL_PIN, true);
    unsigned int i;
    int r;
    stdio_usb_init();
    sleep_ms(5000);
    uint64_t us = time_us_64();                          // monotonic µs since boot
    uint32_t ms = to_ms_since_boot(get_absolute_time()); // ms since boot
    printf(" initial =%" PRIu64 "us (%ums)\n", us, ms);
    gpio_put(SIGNAL_PIN, 1);

    uint64_t us_start = time_us_64();
    uint32_t ms_start = to_ms_since_boot(get_absolute_time());

    printf("Initial = %" PRIu64 " us (%u ms)\n", us_start, ms_start);

        for (size_t m = 0; m < MLEN_COUNT; m++)
    {

        size_t mlen = MLEN_LIST[m];


        for (unsigned int i = 0; i < NTESTS; i++)
        {
            if (test_sign(mlen))
                return 1;

   
        }

    }

    gpio_put(SIGNAL_PIN, 0);

    uint64_t us_end = time_us_64();
    uint32_t ms_end = to_ms_since_boot(get_absolute_time());

    printf("Final   = %" PRIu64 " us (%u ms)\n", us_end, ms_end);

    printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES          = %d\n", CRYPTO_BYTES);

    return 0;
}


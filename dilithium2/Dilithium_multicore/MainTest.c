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

#define MLEN   59
#define NTESTS 100

/* -------------------------------------------------------------
 * LED helpers
 * ------------------------------------------------------------- */
void pico_set_led(bool led_on) {
#if defined(PICO_DEFAULT_LED_PIN)
    gpio_put(PICO_DEFAULT_LED_PIN, led_on);
#elif defined(CYW43_WL_GPIO_LED_PIN)
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, led_on);
#endif
}

int pico_led_init(void) {
#if defined(PICO_DEFAULT_LED_PIN)
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
    return PICO_OK;
#elif defined(CYW43_WL_GPIO_LED_PIN)
    return cyw43_arch_init();
#endif
}

/* -------------------------------------------------------------
 * Dilithium signature test
 * ------------------------------------------------------------- */
static int test_sign(void)
{
    uint8_t m[MLEN] = {0};
    uint8_t sm[MLEN + CRYPTO_BYTES];
    uint8_t m2[MLEN + CRYPTO_BYTES];

    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    size_t mlen, smlen;
    unsigned int j;
    int ret;

    randombytes(m, MLEN);

    crypto_sign_keypair(pk, sk);
    crypto_sign(sm, &smlen, m, MLEN, sk);
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);

    if (ret) {
        printf("ERROR: verification failed\n");
        return 1;
    }

    if (mlen != MLEN) {
        printf("ERROR: message length mismatch\n");
        return 1;
    }

    if (memcmp(m, m2, MLEN)) {
        printf("ERROR: message content mismatch\n");
        return 1;
    }

    /* ---- forgery check ---- */
    randombytes((uint8_t *)&j, sizeof(j));
    do {
        randombytes(m2, 1);
    } while (!m2[0]);

    sm[j % CRYPTO_BYTES] ^= m2[0];

    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
    if (!ret) {
        printf("ERROR: trivial forgery accepted\n");
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
    sleep_ms(5000);   // allow USB to enumerate

    int rc = pico_led_init();
    hard_assert(rc == PICO_OK);

    uint64_t us_start = time_us_64();
    uint32_t ms_start = to_ms_since_boot(get_absolute_time());

    printf("Initial = %" PRIu64 " us (%u ms)\n", us_start, ms_start);

    pico_set_led(true);

    for (unsigned int i = 0; i < NTESTS; i++) {
        if (test_sign()) {
            pico_set_led(false);
            return 1;
        }
    }

    
    uint64_t us_end = time_us_64();
    uint32_t ms_end = to_ms_since_boot(get_absolute_time());
    
    printf("Final   = %" PRIu64 " us (%u ms)\n", us_end, ms_end);
    
    printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES          = %d\n", CRYPTO_BYTES);
    
    pico_set_led(false);
    return 0;
}

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

#define NTESTS 1000
#define SIGNAL_PIN 2
#define MLEN 59
#define CTXLEN 14

// Global buffers to avoid stack overflow and match KEM style
static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[CRYPTO_SECRETKEYBYTES];
static uint8_t m[MLEN + CRYPTO_BYTES];
static uint8_t sm[MLEN + CRYPTO_BYTES];
static size_t smlen;
static uint8_t ctx[CTXLEN] = "mainTest";

int main(void)
{
    stdio_init_all();
    stdio_usb_init();

    gpio_init(SIGNAL_PIN);
    gpio_set_dir(SIGNAL_PIN, GPIO_OUT);
    gpio_put(SIGNAL_PIN, 0);

    sleep_ms(5000);   // Time to open serial monitor

    printf("\n==== DILITHIUM ENERGY PROFILING START ====\n");
    printf("NTESTS = %d\n", NTESTS);

    // Prepare message
    randombytes(m, MLEN);

    /* =========================
       KEYGEN BATCH
       ========================= */
    // printf("\n--- KEYGEN batch start ---\n");
    // gpio_put(SIGNAL_PIN, 1);
    // for (int i = 0; i < NTESTS; i++) {
    //     crypto_sign_keypair(pk, sk);
    // }
    // gpio_put(SIGNAL_PIN, 0);
    // printf("--- KEYGEN batch end ---\n");
    // sleep_ms(3000);


    /* =========================
       SIGN BATCH
       ========================= */
    // printf("\n--- SIGN batch start ---\n");

    // // Need a valid keypair first
    // crypto_sign_keypair(pk, sk);

    // gpio_put(SIGNAL_PIN, 1);

    // for (int i = 0; i < NTESTS; i++) {
    //     // Dilithium signature
    //     crypto_sign(sm, &smlen, m, MLEN, ctx, CTXLEN, sk);
    // }

    // gpio_put(SIGNAL_PIN, 0);
    // printf("--- SIGN batch end ---\n");
    // sleep_ms(3000);


    /* =========================
       VERIFY (OPEN) BATCH
       ========================= */
    printf("\n--- VERIFY batch start ---\n");
    
    // Need a valid signature to verify
    crypto_sign(sm, &smlen, m, MLEN, ctx, CTXLEN, sk);

    gpio_put(SIGNAL_PIN, 1);
    for (int i = 0; i < NTESTS; i++) {
        uint8_t m_out[MLEN + CRYPTO_BYTES];
        size_t mlen_out;
        crypto_sign_open(m_out, &mlen_out, sm, smlen, ctx, CTXLEN, pk);
    }
    gpio_put(SIGNAL_PIN, 0);
    printf("--- VERIFY batch end ---\n");


    printf("\n==== ENERGY PROFILING COMPLETE ====\n");
    printf("CRYPTO_PUBLICKEYBYTES: %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES: %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES (SIG):    %d\n", CRYPTO_BYTES);

    while (1) {
        tight_loop_contents();
    }
}
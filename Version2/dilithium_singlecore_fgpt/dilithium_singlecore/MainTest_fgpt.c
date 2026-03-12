#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "sign.h"
#include "randombytes.h"
#include "profile.h"

#include "pico/stdlib.h"
#include "pico/stdio_usb.h"
#include "pico/time.h"
#include "pico/cyw43_arch.h"

#define SECURITY_LEVEL 5 // only for output format does not actually change the level. If you want to change the level change it in config.h
#define MLEN 59
#define CTXLEN 14
#define NTESTS 10000

void print_profile_results(int prof_runs, double avg_kg, double avg_sign, double avg_ver)
{
    printf("\nphase,component,avg_us,percent\n");

    /* ================= KEYGEN ================= */

    printf("keygen,matrix_expand,%.2f,%.2f\n",
           (double)kg_prof.matrix_expand / prof_runs,
           (100.0 * kg_prof.matrix_expand / prof_runs) / avg_kg);

    printf("keygen,noise_eta,%.2f,%.2f\n",
           (double)kg_prof.noise_eta / prof_runs,
           (100.0 * kg_prof.noise_eta / prof_runs) / avg_kg);

    printf("keygen,ntt,%.2f,%.2f\n",
           (double)kg_prof.ntt / prof_runs,
           (100.0 * kg_prof.ntt / prof_runs) / avg_kg);

    printf("keygen,matmul,%.2f,%.2f\n",
           (double)kg_prof.matmul / prof_runs,
           (100.0 * kg_prof.matmul / prof_runs) / avg_kg);

    printf("keygen,invntt,%.2f,%.2f\n",
           (double)kg_prof.invntt / prof_runs,
           (100.0 * kg_prof.invntt / prof_runs) / avg_kg);

    printf("keygen,pack_pk,%.2f,%.2f\n",
           (double)kg_prof.pack_pk / prof_runs,
           (100.0 * kg_prof.pack_pk / prof_runs) / avg_kg);

    printf("keygen,pack_sk,%.2f,%.2f\n",
           (double)kg_prof.pack_sk / prof_runs,
           (100.0 * kg_prof.pack_sk / prof_runs) / avg_kg);

    /* ================= SIGN ================= */

    printf("sign,unpack_sk,%.2f,%.2f\n",
           (double)sign_prof.unpack_sk / prof_runs,
           (100.0 * sign_prof.unpack_sk / prof_runs) / avg_sign);

    printf("sign,matrix_expand,%.2f,%.2f\n",
           (double)sign_prof.matrix_expand / prof_runs,
           (100.0 * sign_prof.matrix_expand / prof_runs) / avg_sign);

    printf("sign,ntt_secrets,%.2f,%.2f\n",
           (double)sign_prof.ntt_secrets / prof_runs,
           (100.0 * sign_prof.ntt_secrets / prof_runs) / avg_sign);

    printf("sign,sample_y,%.2f,%.2f\n",
           (double)sign_prof.sample_y / prof_runs,
           (100.0 * sign_prof.sample_y / prof_runs) / avg_sign);

    printf("sign,matmul,%.2f,%.2f\n",
           (double)sign_prof.matmul / prof_runs,
           (100.0 * sign_prof.matmul / prof_runs) / avg_sign);

    printf("sign,decompose,%.2f,%.2f\n",
           (double)sign_prof.decompose / prof_runs,
           (100.0 * sign_prof.decompose / prof_runs) / avg_sign);

    printf("sign,challenge,%.2f,%.2f\n",
           (double)sign_prof.challenge / prof_runs,
           (100.0 * sign_prof.challenge / prof_runs) / avg_sign);

    printf("sign,z_vec,%.2f,%.2f\n",
           (double)sign_prof.z_vec / prof_runs,
           (100.0 * sign_prof.z_vec / prof_runs) / avg_sign);

    printf("sign,hint,%.2f,%.2f\n",
           (double)sign_prof.hint / prof_runs,
           (100.0 * sign_prof.hint / prof_runs) / avg_sign);

    printf("sign,pack_sig,%.2f,%.2f\n",
           (double)sign_prof.pack_sig / prof_runs,
           (100.0 * sign_prof.pack_sig / prof_runs) / avg_sign);

    printf("sign,rejection_avg,%.2f,0\n",
           (double)sign_prof.rej_count / prof_runs);

    /* ================= VERIFY ================= */

    printf("verify,unpack,%.2f,%.2f\n",
           (double)ver_prof.unpack / prof_runs,
           (100.0 * ver_prof.unpack / prof_runs) / avg_ver);

    printf("verify,matrix_expand,%.2f,%.2f\n",
           (double)ver_prof.matrix_expand / prof_runs,
           (100.0 * ver_prof.matrix_expand / prof_runs) / avg_ver);

    printf("verify,ntt,%.2f,%.2f\n",
           (double)ver_prof.ntt / prof_runs,
           (100.0 * ver_prof.ntt / prof_runs) / avg_ver);

    printf("verify,matmul,%.2f,%.2f\n",
           (double)ver_prof.matmul / prof_runs,
           (100.0 * ver_prof.matmul / prof_runs) / avg_ver);

    printf("verify,use_hint,%.2f,%.2f\n",
           (double)ver_prof.use_hint / prof_runs,
           (100.0 * ver_prof.use_hint / prof_runs) / avg_ver);

    printf("verify,pack_w1,%.2f,%.2f\n",
           (double)ver_prof.pack_w1 / prof_runs,
           (100.0 * ver_prof.pack_w1 / prof_runs) / avg_ver);
}
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
static int test_sign_timed(uint64_t *d_keygen,
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

    /* Negative test (not timed) */
    if (test_forgery(MLEN))
        return 1;

    uint64_t sum_keygen = 0;
    uint64_t sum_sign = 0;
    uint64_t sum_verify = 0;

    for (unsigned int i = 0; i < NTESTS; i++)
    {
        uint64_t dkg, dsg, dvf;
        if (test_sign_timed(&dkg, &dsg, &dvf))
            return 1;

        sum_keygen += dkg;
        sum_sign += dsg;
        sum_verify += dvf;
    }

    printf("%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
           SECURITY_LEVEL,
           NTESTS,
           (int)MLEN,
           sum_keygen / NTESTS,
           sum_sign / NTESTS,
           sum_verify / NTESTS);

    double avg_kg = (double)sum_keygen / NTESTS;
    double avg_sign = (double)sum_sign / NTESTS;
    double avg_ver = (double)sum_verify / NTESTS;

    print_profile_results(NTESTS, avg_kg, avg_sign, avg_ver);

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

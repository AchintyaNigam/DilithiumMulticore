#ifndef PROFILE_H
#define PROFILE_H

#include <stdint.h>

/* ================= KEYGEN ================= */
typedef struct {
    uint64_t matrix_expand;
    uint64_t noise_eta;      /* s1, s2 sampling */
    uint64_t ntt;
    uint64_t matmul;
    uint64_t invntt;
    uint64_t pack_pk;
    uint64_t pack_sk;
} keygen_profile_t;

/* ================= SIGN ================= */
typedef struct {
    uint64_t unpack_sk;
    uint64_t matrix_expand;
    uint64_t ntt_secrets;    /* NTT(s1), NTT(s2), NTT(t0) */
    uint64_t sample_y;       /* Vector y sampling */
    uint64_t matmul;         /* Az */
    uint64_t decompose;      /* Decompose/w1 packing */
    uint64_t challenge;      /* H(mu, w1) and poly_challenge */
    uint64_t z_vec;          /* z = y + cs1 */
    uint64_t hint;           /* Hint generation and checking */
    uint64_t pack_sig;
    uint32_t rej_count;      /* Number of times loop restarted */
} sign_profile_t;

/* ================= VERIFY ================= */
typedef struct {
    uint64_t unpack;
    uint64_t matrix_expand;
    uint64_t ntt;
    uint64_t matmul;         /* Az - c*t1*2^d */
    uint64_t use_hint;
    uint64_t pack_w1;
} verify_profile_t;

extern keygen_profile_t kg_prof;
extern sign_profile_t sign_prof;
extern verify_profile_t ver_prof;

void profile_reset(void);

#endif
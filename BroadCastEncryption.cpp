
#include "BroadCastEncryption.h"

void BroadCastEncryption::setup(uint32_t n) {

    params *p = new params;
    p->N = n;


    key_pairs *kp = static_cast<key_pairs *>(pbc_malloc(sizeof(struct key_pairs)));
    kp->PK = static_cast<PKEY *>(pbc_malloc(sizeof(struct PKEY)));

    element_init_G1(kp->PK->g1, p->pairing);
    element_random(kp->PK->g1);


    element_init_G2(kp->PK->g2, p->pairing);
    element_random(kp->PK->g2);

    element_t alpha;
    element_init_Zr(alpha, p->pairing);
    element_random(alpha);


    element_t gamma;
    element_init_Zr(alpha, p->pairing);
    element_random(gamma);

    // allocate memory for the  p_i's
    kp->PK->p_i = static_cast<element_t *>(pbc_malloc(2 * p->N * sizeof(element_t)));
    // allocate memory for the  q_i's
    kp->PK->q_i = static_cast<element_t *>(pbc_malloc(p->N * sizeof(element_t)));


    element_init_G1(kp->PK->p_i[0], p->pairing);
    element_pow_zn(kp->PK->p_i[0], kp->PK->g1, alpha);

    //make the exponentiations and store them: p_(i+1) = p_i ^ alpha
    for (u_int64_t i = 0; i < 2 * p->N; i++) {
        element_init_G1(kp->PK->q_i[i], p->pairing);
        element_pow_zn(kp->PK->q_i[i], kp->PK->q_i[i - 1], alpha);
    }

    for (u_int64_t i = 0; i < p->N; i++) {
        element_init_G1(kp->PK->q_i[i], p->pairing);
        element_pow_zn(kp->PK->q_i[i], kp->PK->g2, gamma);
    }


    //compute the secret keys
    for (uint i = 0; i < p->N; i++) {
        element_init_G1(kp->s_key->d_i[i], p->pairing);
        element_pow_zn(kp->s_key->d_i[i], kp->PK->p_i[i], gamma);
    }

    element_clear(alpha);
    element_clear(gamma);

}

void BroadCastEncryption::encrypt(const void *message, cipher_t c,
                                  const pk pkeys, const params *p, const uint32_t user_i) {


    c = static_cast<cipher_t >(pbc_malloc(sizeof(struct ciphertext)));

    c->Hdr = static_cast<element_t *>(pbc_malloc(2*sizeof(element_t)));

    // random k
    element_t k;
    element_init_Zr(k, static_cast<pairing_s *>(p->pairing));
    element_random(k);

    // Compute K
    element_init_GT(c->K, p->pairing);
    pairing_apply(c->K, pkeys->p_i[user_i + 1], pkeys->q_i[0], p->pairing);
    element_pow_zn(c->K, c->K, k);

    //compute C0 = KQ
    element_init_G1(c->Hdr[0], p->pairing);
    element_pow_zn(c->Hdr[0], pkeys->g2, k);

    //compute second part C1 =





}


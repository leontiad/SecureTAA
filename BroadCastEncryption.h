#include <vector>
#include "pbcwrapper/PBC.h"

#ifndef SECURETAA_BROADCASTENCRYPTION_H
#define SECURETAA_BROADCASTENCRYPTION_H


using namespace std;

class BroadCastEncryption {


public:

    typedef struct params {
        pairing_s *pairing; //pairing type
        uint32_t N; //number of users
    };

    typedef struct PKEY {
        element_t g1; // generator in G1
        element_t g2; // generator in G2

        element_t *v;

        element_t *p_i; // = a^i*P 2n elements
        element_t *q_i; // N elements
    } *pk;

    typedef struct SK {
        element_t *d_i;// gamma*p_i
    } *sk;

    typedef struct ciphertext {
        element_t *Hdr; //C0
        element_t K; //C1
    } *cipher_t;


    typedef struct key_pairs {
        PKEY *PK;
        sk s_key;
    };

    /*
    * @brief Setup the Broadcast channel
    *
    */
    void setup(uint32_t n);

private:
    /*
     * @brief Broadcast encryption functionality
     *
     */
    void encrypt(const void *message, cipher_t c,
                 const pk pkeys, const params *p, const uint32_t user_i);

    /*
     * @brief Broadcast decryption functionality
     *
     */
    void *decrypt(const cipher_t *ciphertext, void *message, int userIndex, SK secret_key);

};


#endif //SECURETAA_BROADCASTENCRYPTION_H

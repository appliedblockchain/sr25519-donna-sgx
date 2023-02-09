#ifndef __SR25519_SGX_RANDOM_H__
#define __SR25519_SGX_RANDOM_H__

/*
    a custom randombytes must implement:

    void sr25519_randombytes(void *p, size_t len);
*/

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

static void sr25519_randombytes(void *p, size_t len) {
  sgx_read_rand((unsigned char *)p, len);
}

#endif
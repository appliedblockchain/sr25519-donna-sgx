#ifndef sr25519_donna_core_H
#define sr25519_donna_core_H

#if !defined(SGX)
#include "sr25519-randombytes-default.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(SGX)
SR25519_DONNA_EXPORT
#endif
void sr25519_donna_misuse(void)
            __attribute__ ((noreturn));

#ifdef __cplusplus
}
#endif

#endif

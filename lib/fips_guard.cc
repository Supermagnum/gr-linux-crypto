/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * OpenSSL FIPS provider load at module init. Fails loudly if unavailable.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef GR_LINUX_CRYPTO_FIPS

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <cstdio>
#include <cstdlib>

namespace {

static bool s_fips_loaded = false;

static bool load_fips_provider(void)
{
    if (s_fips_loaded)
        return true;
    OSSL_PROVIDER* fips = OSSL_PROVIDER_load(nullptr, "fips");
    if (fips == nullptr) {
        std::fprintf(stderr,
                     "gr-linux-crypto: FIPS provider required (GR_LINUX_CRYPTO_FIPS=ON) but "
                     "OpenSSL FIPS provider could not be loaded. Aborting.\n");
        std::abort();
    }
    OSSL_PROVIDER* base = OSSL_PROVIDER_load(nullptr, "base");
    if (base == nullptr) {
        OSSL_PROVIDER_unload(fips);
        std::fprintf(stderr,
                     "gr-linux-crypto: Base provider required with FIPS. Aborting.\n");
        std::abort();
    }
    if (EVP_default_properties_enable_fips(nullptr, 1) != 1) {
        OSSL_PROVIDER_unload(base);
        OSSL_PROVIDER_unload(fips);
        std::fprintf(stderr,
                     "gr-linux-crypto: FIPS provider loaded but could not enable FIPS mode. "
                     "Aborting.\n");
        std::abort();
    }
    s_fips_loaded = true;
    return true;
}

struct FipsInit
{
    FipsInit() { load_fips_provider(); }
} s_fips_init;

} // namespace

extern "C" {

int gr_linux_crypto_fips_ensure_loaded(void)
{
    return load_fips_provider() ? 1 : 0;
}

} // extern "C"

#else

extern "C" {

int gr_linux_crypto_fips_ensure_loaded(void)
{
    (void)0;
    return 1; /* FIPS not required */
}

} // extern "C"

#endif /* GR_LINUX_CRYPTO_FIPS */

/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * When GR_LINUX_CRYPTO_FIPS is defined, the FIPS provider is loaded at
 * module initialization and must be active for all crypto operations.
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_FIPS_GUARD_H
#define INCLUDED_GR_LINUX_CRYPTO_FIPS_GUARD_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \brief Ensure the OpenSSL FIPS provider is loaded and active.
 *
 * When built with GR_LINUX_CRYPTO_FIPS=ON, the provider is loaded at
 * library load time; this function returns 1 if FIPS is active, 0 otherwise.
 * When FIPS is not enabled at build time, returns 1 (no requirement).
 */
int gr_linux_crypto_fips_ensure_loaded(void);

#ifdef __cplusplus
}
#endif

#endif /* INCLUDED_GR_LINUX_CRYPTO_FIPS_GUARD_H */

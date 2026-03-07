/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * BSI TR-02102 algorithm boundary enforcement. When GR_LINUX_CRYPTO_STRICT_BSI
 * is defined, runtime checks reject any algorithm not in the approved list.
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_BSI_BOUNDARY_H
#define INCLUDED_GR_LINUX_CRYPTO_BSI_BOUNDARY_H

#include <string>

namespace gr {
namespace linux_crypto {

/*!
 * \brief Check if an ECC curve name is BSI TR-02102 approved.
 * \param curve Curve name (e.g. "brainpoolP256r1").
 * \return true if approved, false otherwise.
 * When GR_LINUX_CRYPTO_STRICT_BSI is not defined, always returns true.
 */
bool bsi_allow_curve(const std::string& curve);

/*!
 * \brief Check if a symmetric cipher is BSI TR-02102 approved.
 * \param cipher Cipher name (e.g. "aes-256-gcm", "chacha20-poly1305").
 * \return true if approved, false otherwise.
 */
bool bsi_allow_symmetric(const std::string& cipher);

/*!
 * \brief Check if a hash algorithm is BSI TR-02102 approved.
 * \param hash Hash name (e.g. "sha256", "sha-256").
 * \return true if approved, false otherwise.
 */
bool bsi_allow_hash(const std::string& hash);

/*!
 * \brief Enforce BSI curve: if not approved, throw std::invalid_argument with
 *        algorithm name and BSI reference.
 */
void bsi_require_curve(const std::string& curve);

/*!
 * \brief Enforce BSI symmetric cipher: if not approved, throw.
 */
void bsi_require_symmetric(const std::string& cipher);

/*!
 * \brief Enforce BSI hash: if not approved, throw.
 */
void bsi_require_hash(const std::string& hash);

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_GR_LINUX_CRYPTO_BSI_BOUNDARY_H */

/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * gr-linux-crypto is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * gr-linux-crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gr-linux-crypto; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_ENCRYPT_H
#define INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_ENCRYPT_H

#include <gnuradio/sync_block.h>
#include <gnuradio/linux_crypto/api.h>
#include <gnuradio/linux_crypto/brainpool_ec_impl.h>
#include <string>
#include <vector>

namespace gr {
namespace linux_crypto {

/*!
 * \brief Brainpool ECIES encryption block
 * \ingroup linux_crypto
 *
 * This block implements ECIES (Elliptic Curve Integrated Encryption Scheme)
 * encryption using Brainpool elliptic curves. The encryption process:
 * 1. Generates an ephemeral key pair
 * 2. Performs ECDH key exchange with recipient's public key
 * 3. Derives symmetric encryption key using HKDF
 * 4. Encrypts plaintext using AES-GCM
 * 5. Outputs ephemeral public key + ciphertext + authentication tag
 *
 * The recipient's public key can be provided via constructor parameter
 * or via message port for dynamic key updates.
 */
class LINUX_CRYPTO_API brainpool_ecies_encrypt : virtual public gr::sync_block
{
public:
    typedef std::shared_ptr<brainpool_ecies_encrypt> sptr;

    /*!
     * \brief Make a Brainpool ECIES encryption block
     *
     * \param curve Brainpool curve to use ("brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1")
     * \param recipient_public_key_pem Recipient's public key in PEM format (optional, can be set via message port)
     * \param kdf_info Optional context information for HKDF key derivation
     * \return shared pointer to the new block
     */
    static sptr make(const std::string& curve = "brainpoolP256r1",
                    const std::string& recipient_public_key_pem = "",
                    const std::string& kdf_info = "gr-linux-crypto-ecies-v1");

    /*!
     * \brief Set recipient's public key
     * \param public_key_pem Public key in PEM format
     */
    virtual void set_recipient_public_key(const std::string& public_key_pem) = 0;

    /*!
     * \brief Get current recipient's public key
     * \return Public key in PEM format (empty if not set)
     */
    virtual std::string get_recipient_public_key() const = 0;

    /*!
     * \brief Set KDF info parameter
     * \param kdf_info Context information for HKDF
     */
    virtual void set_kdf_info(const std::string& kdf_info) = 0;

    /*!
     * \brief Get current KDF info parameter
     * \return Current KDF info string
     */
    virtual std::string get_kdf_info() const = 0;

    /*!
     * \brief Get current curve
     * \return Curve name
     */
    virtual std::string get_curve() const = 0;
};

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_ENCRYPT_H */


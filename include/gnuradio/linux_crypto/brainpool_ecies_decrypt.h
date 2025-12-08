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

#ifndef INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_DECRYPT_H
#define INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_DECRYPT_H

#include <gnuradio/sync_block.h>
#include <gnuradio/linux_crypto/api.h>
#include <gnuradio/linux_crypto/brainpool_ec_impl.h>
#include <string>
#include <vector>

namespace gr {
namespace linux_crypto {

/*!
 * \brief Brainpool ECIES decryption block
 * \ingroup linux_crypto
 *
 * This block implements ECIES (Elliptic Curve Integrated Encryption Scheme)
 * decryption using Brainpool elliptic curves. The decryption process:
 * 1. Extracts ephemeral public key from encrypted data
 * 2. Performs ECDH key exchange with recipient's private key
 * 3. Derives symmetric decryption key using HKDF
 * 4. Decrypts ciphertext using AES-GCM with authentication
 * 5. Outputs plaintext (only if authentication succeeds)
 *
 * The recipient's private key can be provided via constructor parameter
 * or via message port for dynamic key updates.
 */
class LINUX_CRYPTO_API brainpool_ecies_decrypt : virtual public gr::sync_block
{
public:
    typedef std::shared_ptr<brainpool_ecies_decrypt> sptr;

    /*!
     * \brief Make a Brainpool ECIES decryption block
     *
     * \param curve Brainpool curve to use ("brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1")
     * \param recipient_private_key_pem Recipient's private key in PEM format (optional, can be set via message port)
     * \param private_key_password Password for encrypted private key (empty if unencrypted)
     * \param kdf_info Optional context information for HKDF key derivation (must match encryption)
     * \return shared pointer to the new block
     */
    static sptr make(const std::string& curve = "brainpoolP256r1",
                    const std::string& recipient_private_key_pem = "",
                    const std::string& private_key_password = "",
                    const std::string& kdf_info = "gr-linux-crypto-ecies-v1");

    /*!
     * \brief Set recipient's private key
     * \param private_key_pem Private key in PEM format
     * \param password Password for encrypted private key (empty if unencrypted)
     */
    virtual void set_recipient_private_key(const std::string& private_key_pem,
                                          const std::string& password = "") = 0;

    /*!
     * \brief Get current recipient's private key status
     * \return true if private key is loaded
     */
    virtual bool is_private_key_loaded() const = 0;

    /*!
     * \brief Set KDF info parameter
     * \param kdf_info Context information for HKDF (must match encryption)
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

#endif /* INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_DECRYPT_H */


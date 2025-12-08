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

#ifndef INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_MULTI_ENCRYPT_H
#define INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_MULTI_ENCRYPT_H

#include <gnuradio/sync_block.h>
#include <gnuradio/linux_crypto/api.h>
#include <gnuradio/linux_crypto/brainpool_ec_impl.h>
#include <string>
#include <vector>

namespace gr {
namespace linux_crypto {

/*!
 * \brief Brainpool ECIES multi-recipient encryption block
 * \ingroup linux_crypto
 *
 * This block implements multi-recipient ECIES encryption using Brainpool
 * elliptic curves. Supports up to 25 recipients.
 *
 * The encryption process:
 * 1. Generates a symmetric key (AES-256)
 * 2. For each recipient, encrypts the symmetric key using ECIES
 * 3. Encrypts the payload data using AES-GCM with the symmetric key
 * 4. Outputs formatted block with header, recipient blocks, and encrypted data
 *
 * Recipients are identified by radio amateur callsigns, and their public
 * keys are looked up from a key store.
 */
class LINUX_CRYPTO_API brainpool_ecies_multi_encrypt : virtual public gr::sync_block
{
public:
    typedef std::shared_ptr<brainpool_ecies_multi_encrypt> sptr;

    /*!
     * \brief Make a Brainpool ECIES multi-recipient encryption block
     *
     * \param curve Brainpool curve to use ("brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1")
     * \param callsigns Vector of recipient callsigns (1-25 callsigns)
     * \param key_store_path Path to key store file (empty for default)
     * \param kdf_info Optional context information for HKDF key derivation
     * \return shared pointer to the new block
     */
    static sptr make(const std::string& curve = "brainpoolP256r1",
                    const std::vector<std::string>& callsigns = {},
                    const std::string& key_store_path = "",
                    const std::string& kdf_info = "gr-linux-crypto-ecies-v1");

    /*!
     * \brief Set recipient callsigns
     * \param callsigns Vector of recipient callsigns (1-25)
     */
    virtual void set_callsigns(const std::vector<std::string>& callsigns) = 0;

    /*!
     * \brief Get current recipient callsigns
     * \return Vector of callsigns
     */
    virtual std::vector<std::string> get_callsigns() const = 0;

    /*!
     * \brief Add a recipient callsign
     * \param callsign Callsign to add
     * \return True if added successfully (max 25 recipients)
     */
    virtual bool add_callsign(const std::string& callsign) = 0;

    /*!
     * \brief Remove a recipient callsign
     * \param callsign Callsign to remove
     * \return True if removed successfully
     */
    virtual bool remove_callsign(const std::string& callsign) = 0;

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

    /*!
     * \brief Get maximum number of recipients
     * \return Maximum recipients (25)
     */
    static constexpr size_t MAX_RECIPIENTS = 25;
};

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_MULTI_ENCRYPT_H */

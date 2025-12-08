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

#ifndef INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECDSA_VERIFY_H
#define INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECDSA_VERIFY_H

#include <gnuradio/sync_block.h>
#include <gnuradio/linux_crypto/api.h>
#include <gnuradio/linux_crypto/brainpool_ec_impl.h>
#include <string>
#include <vector>

namespace gr {
namespace linux_crypto {

/*!
 * \brief Brainpool ECDSA verification block
 * \ingroup linux_crypto
 *
 * This block implements ECDSA (Elliptic Curve Digital Signature Algorithm)
 * signature verification using Brainpool elliptic curves. The verification process:
 * 1. Takes input data stream (data + signature)
 * 2. Verifies signature using public key and hash algorithm
 * 3. Outputs original data if verification succeeds, zeros if it fails
 *
 * The public key can be provided via constructor parameter
 * or via message port for dynamic key updates.
 */
class LINUX_CRYPTO_API brainpool_ecdsa_verify : virtual public gr::sync_block
{
public:
    typedef std::shared_ptr<brainpool_ecdsa_verify> sptr;

    /*!
     * \brief Make a Brainpool ECDSA verification block
     *
     * \param curve Brainpool curve to use ("brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1")
     * \param public_key_pem Public key in PEM format (optional, can be set via message port)
     * \param hash_algorithm Hash algorithm for verification ("sha256", "sha384", "sha512")
     * \return shared pointer to the new block
     */
    static sptr make(const std::string& curve = "brainpoolP256r1",
                    const std::string& public_key_pem = "",
                    const std::string& hash_algorithm = "sha256");

    /*!
     * \brief Set public key
     * \param public_key_pem Public key in PEM format
     */
    virtual void set_public_key(const std::string& public_key_pem) = 0;

    /*!
     * \brief Get current public key
     * \return Public key in PEM format (empty if not set)
     */
    virtual std::string get_public_key() const = 0;

    /*!
     * \brief Set hash algorithm
     * \param hash_algorithm Hash algorithm ("sha256", "sha384", "sha512")
     */
    virtual void set_hash_algorithm(const std::string& hash_algorithm) = 0;

    /*!
     * \brief Get current hash algorithm
     * \return Hash algorithm name
     */
    virtual std::string get_hash_algorithm() const = 0;

    /*!
     * \brief Get current curve
     * \return Curve name
     */
    virtual std::string get_curve() const = 0;
};

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECDSA_VERIFY_H */


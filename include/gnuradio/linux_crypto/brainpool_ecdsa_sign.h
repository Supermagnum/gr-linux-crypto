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

#ifndef INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECDSA_SIGN_H
#define INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECDSA_SIGN_H

#include <gnuradio/sync_block.h>
#include <gnuradio/linux_crypto/api.h>
#include <gnuradio/linux_crypto/brainpool_ec_impl.h>
#include <string>
#include <vector>

namespace gr {
namespace linux_crypto {

/*!
 * \brief Brainpool ECDSA signing block
 * \ingroup linux_crypto
 *
 * This block implements ECDSA (Elliptic Curve Digital Signature Algorithm)
 * signing using Brainpool elliptic curves. The signing process:
 * 1. Takes input data stream
 * 2. Signs data using private key and hash algorithm
 * 3. Outputs data + signature (DER encoded)
 *
 * The private key can be provided via constructor parameter
 * or via message port for dynamic key updates.
 */
class LINUX_CRYPTO_API brainpool_ecdsa_sign : virtual public gr::sync_block
{
public:
    typedef std::shared_ptr<brainpool_ecdsa_sign> sptr;

    /*!
     * \brief Make a Brainpool ECDSA signing block
     *
     * \param curve Brainpool curve to use ("brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1")
     * \param private_key_pem Private key in PEM format (optional, can be set via message port)
     * \param hash_algorithm Hash algorithm for signing ("sha256", "sha384", "sha512")
     * \return shared pointer to the new block
     */
    static sptr make(const std::string& curve = "brainpoolP256r1",
                    const std::string& private_key_pem = "",
                    const std::string& hash_algorithm = "sha256");

    /*!
     * \brief Set private key
     * \param private_key_pem Private key in PEM format
     */
    virtual void set_private_key(const std::string& private_key_pem) = 0;

    /*!
     * \brief Get current private key
     * \return Private key in PEM format (empty if not set)
     */
    virtual std::string get_private_key() const = 0;

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

#endif /* INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECDSA_SIGN_H */


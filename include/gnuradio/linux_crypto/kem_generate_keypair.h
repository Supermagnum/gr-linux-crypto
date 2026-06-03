/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_KEM_GENERATE_KEYPAIR_H
#define INCLUDED_GR_LINUX_CRYPTO_KEM_GENERATE_KEYPAIR_H

#include <gnuradio/block.h>
#include <gnuradio/linux_crypto/api.h>
#include <string>

namespace gr {
namespace linux_crypto {

/*!
 * \brief Generate and save an X-Wing KEM keypair (libsodium)
 * \ingroup linux_crypto
 *
 * Writes raw public and secret keys to the configured paths. Trigger via
 * message port ``generate`` or call generate_keypair() from Python.
 */
class LINUX_CRYPTO_API kem_generate_keypair : virtual public gr::block
{
public:
    typedef std::shared_ptr<kem_generate_keypair> sptr;

    /*!
     * \param public_key_file Output path for public key bytes.
     * \param secret_key_file Output path for secret key bytes.
     * \param generate_on_start If true, write keys when the block is constructed.
     */
    static sptr make(const std::string& public_key_file,
                     const std::string& secret_key_file,
                     bool generate_on_start = true);

    virtual bool generate_keypair() = 0;
    virtual void set_public_key_file(const std::string& path) = 0;
    virtual void set_secret_key_file(const std::string& path) = 0;
    virtual std::string public_key_file() const = 0;
    virtual std::string secret_key_file() const = 0;
};

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_GR_LINUX_CRYPTO_KEM_GENERATE_KEYPAIR_H */

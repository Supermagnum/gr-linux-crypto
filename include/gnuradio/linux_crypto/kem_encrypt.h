/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_KEM_ENCRYPT_H
#define INCLUDED_GR_LINUX_CRYPTO_KEM_ENCRYPT_H

#include <gnuradio/block.h>
#include <gnuradio/linux_crypto/api.h>
#include <string>

namespace gr {
namespace linux_crypto {

/*!
 * \brief X-Wing KEM encrypt + secretbox PDU block (libsodium)
 * \ingroup linux_crypto
 *
 * Accepts a PDU (PMT uniform vector or blob) on message port ``in`` and emits
 * a PDU on ``out`` containing KEM ciphertext, nonce, and secretbox ciphertext.
 * Uses crypto_kem_enc() (X-Wing) and crypto_secretbox_easy().
 */
class LINUX_CRYPTO_API kem_encrypt : virtual public gr::block
{
public:
    typedef std::shared_ptr<kem_encrypt> sptr;

    /*!
     * \param public_key_file Path to raw X-Wing public key
     *        (crypto_kem_PUBLICKEYBYTES bytes).
     */
    static sptr make(const std::string& public_key_file);

    virtual void set_public_key_file(const std::string& path) = 0;
    virtual std::string public_key_file() const = 0;
};

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_GR_LINUX_CRYPTO_KEM_ENCRYPT_H */

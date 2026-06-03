/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_KEM_DECRYPT_H
#define INCLUDED_GR_LINUX_CRYPTO_KEM_DECRYPT_H

#include <gnuradio/block.h>
#include <gnuradio/linux_crypto/api.h>
#include <string>

namespace gr {
namespace linux_crypto {

/*!
 * \brief X-Wing KEM decrypt + secretbox PDU block (libsodium)
 * \ingroup linux_crypto
 *
 * Accepts KEM PDUs from kem_encrypt on message port ``in`` and emits the
 * recovered plaintext PDU on ``out``. Uses crypto_kem_dec() and
 * crypto_secretbox_open_easy().
 */
class LINUX_CRYPTO_API kem_decrypt : virtual public gr::block
{
public:
    typedef std::shared_ptr<kem_decrypt> sptr;

    /*!
     * \param secret_key_file Path to raw X-Wing secret key
     *        (crypto_kem_SECRETKEYBYTES bytes).
     */
    static sptr make(const std::string& secret_key_file);

    virtual void set_secret_key_file(const std::string& path) = 0;
    virtual std::string secret_key_file() const = 0;
};

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_GR_LINUX_CRYPTO_KEM_DECRYPT_H */

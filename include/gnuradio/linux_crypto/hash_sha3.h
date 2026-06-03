/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_HASH_SHA3_H
#define INCLUDED_GR_LINUX_CRYPTO_HASH_SHA3_H

#include <gnuradio/block.h>
#include <gnuradio/linux_crypto/api.h>

namespace gr {
namespace linux_crypto {

/*!
 * \brief SHA3-256 / SHA3-512 PDU hash block (libsodium)
 * \ingroup linux_crypto
 */
class LINUX_CRYPTO_API hash_sha3 : virtual public gr::block
{
public:
    typedef std::shared_ptr<hash_sha3> sptr;

    /*!
     * \param digest_bits 256 for SHA3-256, 512 for SHA3-512.
     */
    static sptr make(int digest_bits = 256);

    virtual void set_digest_bits(int digest_bits) = 0;
    virtual int digest_bits() const = 0;
};

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_GR_LINUX_CRYPTO_HASH_SHA3_H */

/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_HASH_SHA3_IMPL_H
#define INCLUDED_GR_LINUX_CRYPTO_HASH_SHA3_IMPL_H

#ifdef HAVE_SODIUM

#include <gnuradio/linux_crypto/hash_sha3.h>
#include <pmt/pmt.h>
#include <mutex>

namespace gr {
namespace linux_crypto {

class hash_sha3_impl : public hash_sha3
{
private:
    int d_digest_bits;
    mutable std::mutex d_mutex;

    void handle_pdu(pmt::pmt_t msg);

public:
    explicit hash_sha3_impl(int digest_bits);
    ~hash_sha3_impl() override;

    void set_digest_bits(int digest_bits) override;
    int digest_bits() const override;
};

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_SODIUM

#endif /* INCLUDED_GR_LINUX_CRYPTO_HASH_SHA3_IMPL_H */

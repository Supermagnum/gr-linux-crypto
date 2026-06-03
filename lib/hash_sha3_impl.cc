/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SODIUM

#include "hash_sha3_impl.h"
#include <gnuradio/io_signature.h>
#include <pmt/pmt.h>
#include <sodium.h>
#include <stdexcept>

namespace gr {
namespace linux_crypto {

static std::vector<uint8_t> pmt_to_bytes(pmt::pmt_t msg)
{
    if (pmt::is_u8vector(msg)) {
        return pmt::u8vector_elements(msg);
    }
    if (pmt::is_blob(msg)) {
        const size_t len = pmt::blob_length(msg);
        const auto* data = static_cast<const uint8_t*>(pmt::blob_data(msg));
        return std::vector<uint8_t>(data, data + len);
    }
    throw std::runtime_error("hash_sha3: expected u8vector or blob PDU");
}

static int normalize_digest_bits(int bits)
{
    if (bits == 256 || bits == 512) {
        return bits;
    }
    return 256;
}

hash_sha3::sptr hash_sha3::make(int digest_bits)
{
    return gnuradio::get_initial_sptr(new hash_sha3_impl(digest_bits));
}

hash_sha3_impl::hash_sha3_impl(int digest_bits)
    : gr::block("hash_sha3",
                gr::io_signature::make(0, 0, 0),
                gr::io_signature::make(0, 0, 0)),
      d_digest_bits(normalize_digest_bits(digest_bits))
{
    if (sodium_init() < 0) {
        throw std::runtime_error("hash_sha3: sodium_init failed");
    }
    message_port_register_in(pmt::mp("in"));
    message_port_register_out(pmt::mp("out"));
    set_msg_handler(pmt::mp("in"), [this](pmt::pmt_t msg) { handle_pdu(msg); });
}

hash_sha3_impl::~hash_sha3_impl() = default;

void hash_sha3_impl::set_digest_bits(int digest_bits)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    d_digest_bits = normalize_digest_bits(digest_bits);
}

int hash_sha3_impl::digest_bits() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_digest_bits;
}

void hash_sha3_impl::handle_pdu(pmt::pmt_t msg)
{
    std::vector<uint8_t> input;
    try {
        input = pmt_to_bytes(msg);
    } catch (const std::exception& e) {
        d_logger->error("{:s}", e.what());
        return;
    }

    int bits = 256;
    {
        std::lock_guard<std::mutex> lock(d_mutex);
        bits = d_digest_bits;
    }

    std::vector<uint8_t> digest;
    const unsigned long long inlen = static_cast<unsigned long long>(input.size());
    if (bits == 512) {
        digest.resize(crypto_hash_sha3512_BYTES);
        if (crypto_hash_sha3512(digest.data(), input.data(), inlen) != 0) {
            d_logger->error("hash_sha3: crypto_hash_sha3512 failed");
            return;
        }
    } else {
        digest.resize(crypto_hash_sha3256_BYTES);
        if (crypto_hash_sha3256(digest.data(), input.data(), inlen) != 0) {
            d_logger->error("hash_sha3: crypto_hash_sha3256 failed");
            return;
        }
    }

    message_port_pub(pmt::mp("out"), pmt::init_u8vector(digest.size(), digest));
}

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_SODIUM

/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_KEM_ENCRYPT_IMPL_H
#define INCLUDED_GR_LINUX_CRYPTO_KEM_ENCRYPT_IMPL_H

#ifdef HAVE_SODIUM

#include <gnuradio/linux_crypto/kem_encrypt.h>
#include <pmt/pmt.h>
#include <mutex>
#include <string>
#include <vector>

namespace gr {
namespace linux_crypto {

namespace kem_pdu {

constexpr char MAGIC[4] = { 'G', 'K', 'E', 'M' };

void append_u32_be(std::vector<uint8_t>& out, uint32_t v);
bool read_u32_be(const std::vector<uint8_t>& in, size_t& off, uint32_t& v);
std::vector<uint8_t> pack(const std::vector<uint8_t>& kem_ct,
                            const std::vector<uint8_t>& nonce,
                            const std::vector<uint8_t>& box);
bool unpack(const std::vector<uint8_t>& in,
            std::vector<uint8_t>& kem_ct,
            std::vector<uint8_t>& nonce,
            std::vector<uint8_t>& box);

} // namespace kem_pdu

class kem_encrypt_impl : public kem_encrypt
{
private:
    std::string d_public_key_file;
    std::vector<uint8_t> d_public_key;
    mutable std::mutex d_mutex;

    bool reload_public_key();
    void handle_pdu(pmt::pmt_t msg);

public:
    kem_encrypt_impl(const std::string& public_key_file);
    ~kem_encrypt_impl() override;

    void set_public_key_file(const std::string& path) override;
    std::string public_key_file() const override;
};

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_SODIUM

#endif /* INCLUDED_GR_LINUX_CRYPTO_KEM_ENCRYPT_IMPL_H */

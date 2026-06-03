/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_KEM_DECRYPT_IMPL_H
#define INCLUDED_GR_LINUX_CRYPTO_KEM_DECRYPT_IMPL_H

#ifdef HAVE_SODIUM

#include <gnuradio/linux_crypto/kem_decrypt.h>
#include <pmt/pmt.h>
#include <mutex>
#include <string>
#include <vector>

namespace gr {
namespace linux_crypto {

class kem_decrypt_impl : public kem_decrypt
{
private:
    std::string d_secret_key_file;
    std::vector<uint8_t> d_secret_key;
    mutable std::mutex d_mutex;

    bool reload_secret_key();
    void handle_pdu(pmt::pmt_t msg);

public:
    kem_decrypt_impl(const std::string& secret_key_file);
    ~kem_decrypt_impl() override;

    void set_secret_key_file(const std::string& path) override;
    std::string secret_key_file() const override;
};

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_SODIUM

#endif /* INCLUDED_GR_LINUX_CRYPTO_KEM_DECRYPT_IMPL_H */

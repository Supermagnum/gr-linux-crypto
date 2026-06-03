/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_KEM_GENERATE_KEYPAIR_IMPL_H
#define INCLUDED_GR_LINUX_CRYPTO_KEM_GENERATE_KEYPAIR_IMPL_H

#ifdef HAVE_SODIUM

#include <gnuradio/linux_crypto/kem_generate_keypair.h>
#include <pmt/pmt.h>
#include <mutex>
#include <string>

namespace gr {
namespace linux_crypto {

class kem_generate_keypair_impl : public kem_generate_keypair
{
private:
    std::string d_public_key_file;
    std::string d_secret_key_file;
    mutable std::mutex d_mutex;

    void handle_generate(pmt::pmt_t msg);

public:
    kem_generate_keypair_impl(const std::string& public_key_file,
                              const std::string& secret_key_file,
                              bool generate_on_start);
    ~kem_generate_keypair_impl() override;

    bool generate_keypair() override;
    void set_public_key_file(const std::string& path) override;
    void set_secret_key_file(const std::string& path) override;
    std::string public_key_file() const override;
    std::string secret_key_file() const override;
};

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_SODIUM

#endif /* INCLUDED_GR_LINUX_CRYPTO_KEM_GENERATE_KEYPAIR_IMPL_H */

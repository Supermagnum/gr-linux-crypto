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

#include "kem_generate_keypair_impl.h"
#include <gnuradio/io_signature.h>
#include <pmt/pmt.h>
#include <sodium.h>
#include <fstream>
#include <stdexcept>

namespace gr {
namespace linux_crypto {

kem_generate_keypair::sptr
kem_generate_keypair::make(const std::string& public_key_file,
                           const std::string& secret_key_file,
                           bool generate_on_start)
{
    return gnuradio::get_initial_sptr(
        new kem_generate_keypair_impl(public_key_file, secret_key_file, generate_on_start));
}

kem_generate_keypair_impl::kem_generate_keypair_impl(const std::string& public_key_file,
                                                     const std::string& secret_key_file,
                                                     bool generate_on_start)
    : gr::block("kem_generate_keypair",
                gr::io_signature::make(0, 0, 0),
                gr::io_signature::make(0, 0, 0)),
      d_public_key_file(public_key_file),
      d_secret_key_file(secret_key_file)
{
    if (sodium_init() < 0) {
        throw std::runtime_error("kem_generate_keypair: sodium_init failed");
    }
    message_port_register_in(pmt::mp("generate"));
    message_port_register_out(pmt::mp("status"));
    set_msg_handler(pmt::mp("generate"), [this](pmt::pmt_t msg) { handle_generate(msg); });
    if (generate_on_start) {
        if (!generate_keypair()) {
            throw std::runtime_error("kem_generate_keypair: initial key generation failed");
        }
    }
}

kem_generate_keypair_impl::~kem_generate_keypair_impl() = default;

bool kem_generate_keypair_impl::generate_keypair()
{
    std::lock_guard<std::mutex> lock(d_mutex);
    if (d_public_key_file.empty() || d_secret_key_file.empty()) {
        return false;
    }

    std::vector<unsigned char> pk(crypto_kem_PUBLICKEYBYTES);
    std::vector<unsigned char> sk(crypto_kem_SECRETKEYBYTES);
    if (crypto_kem_keypair(pk.data(), sk.data()) != 0) {
        return false;
    }

    std::ofstream pk_out(d_public_key_file, std::ios::binary | std::ios::trunc);
    if (!pk_out) {
        return false;
    }
    pk_out.write(reinterpret_cast<const char*>(pk.data()),
                 static_cast<std::streamsize>(pk.size()));
    if (!pk_out) {
        return false;
    }

    std::ofstream sk_out(d_secret_key_file, std::ios::binary | std::ios::trunc);
    if (!sk_out) {
        return false;
    }
    sk_out.write(reinterpret_cast<const char*>(sk.data()),
                 static_cast<std::streamsize>(sk.size()));
    if (!sk_out) {
        return false;
    }

    sodium_memzero(sk.data(), sk.size());
    return true;
}

void kem_generate_keypair_impl::handle_generate(pmt::pmt_t)
{
    const bool ok = generate_keypair();
    const std::string status = ok ? "ok" : "error";
    message_port_pub(pmt::mp("status"), pmt::mp(status));
}

void kem_generate_keypair_impl::set_public_key_file(const std::string& path)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    d_public_key_file = path;
}

void kem_generate_keypair_impl::set_secret_key_file(const std::string& path)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    d_secret_key_file = path;
}

std::string kem_generate_keypair_impl::public_key_file() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_public_key_file;
}

std::string kem_generate_keypair_impl::secret_key_file() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_secret_key_file;
}

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_SODIUM

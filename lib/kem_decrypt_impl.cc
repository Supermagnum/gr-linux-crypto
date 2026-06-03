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

#include "kem_decrypt_impl.h"
#include "kem_encrypt_impl.h"
#include <gnuradio/io_signature.h>
#include <pmt/pmt.h>
#include <sodium.h>
#include <fstream>
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
    throw std::runtime_error("kem_decrypt: expected u8vector or blob PDU");
}

kem_decrypt::sptr kem_decrypt::make(const std::string& secret_key_file)
{
    return gnuradio::get_initial_sptr(new kem_decrypt_impl(secret_key_file));
}

kem_decrypt_impl::kem_decrypt_impl(const std::string& secret_key_file)
    : gr::block("kem_decrypt",
                gr::io_signature::make(0, 0, 0),
                gr::io_signature::make(0, 0, 0)),
      d_secret_key_file(secret_key_file)
{
    if (sodium_init() < 0) {
        throw std::runtime_error("kem_decrypt: sodium_init failed");
    }
    message_port_register_in(pmt::mp("in"));
    message_port_register_out(pmt::mp("out"));
    set_msg_handler(pmt::mp("in"), [this](pmt::pmt_t msg) { handle_pdu(msg); });
    if (!reload_secret_key()) {
        throw std::runtime_error("kem_decrypt: failed to load secret key from " +
                                 secret_key_file);
    }
}

kem_decrypt_impl::~kem_decrypt_impl() = default;

bool kem_decrypt_impl::reload_secret_key()
{
    std::lock_guard<std::mutex> lock(d_mutex);
    if (d_secret_key_file.empty()) {
        return false;
    }
    std::ifstream in(d_secret_key_file, std::ios::binary);
    if (!in) {
        return false;
    }
    d_secret_key.resize(crypto_kem_SECRETKEYBYTES);
    in.read(reinterpret_cast<char*>(d_secret_key.data()),
            static_cast<std::streamsize>(d_secret_key.size()));
    return in.gcount() == static_cast<std::streamsize>(d_secret_key.size());
}

void kem_decrypt_impl::set_secret_key_file(const std::string& path)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    d_secret_key_file = path;
    if (!reload_secret_key()) {
        throw std::runtime_error("kem_decrypt: failed to load secret key from " + path);
    }
}

std::string kem_decrypt_impl::secret_key_file() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_secret_key_file;
}

void kem_decrypt_impl::handle_pdu(pmt::pmt_t msg)
{
    std::vector<uint8_t> framed;
    try {
        framed = pmt_to_bytes(msg);
    } catch (const std::exception& e) {
        d_logger->error("{:s}", e.what());
        return;
    }

    std::vector<uint8_t> kem_ct;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> box;
    if (!kem_pdu::unpack(framed, kem_ct, nonce, box)) {
        d_logger->error("kem_decrypt: invalid KEM PDU framing");
        return;
    }

    std::vector<uint8_t> sk;
    {
        std::lock_guard<std::mutex> lock(d_mutex);
        sk = d_secret_key;
    }
    if (sk.size() != crypto_kem_SECRETKEYBYTES) {
        d_logger->error("kem_decrypt: invalid secret key size");
        return;
    }

    std::vector<uint8_t> ss(crypto_kem_SHAREDSECRETBYTES);
    if (crypto_kem_dec(ss.data(), kem_ct.data(), sk.data()) != 0) {
        d_logger->error("kem_decrypt: crypto_kem_dec failed");
        sodium_memzero(ss.data(), ss.size());
        return;
    }

    const unsigned long long clen = static_cast<unsigned long long>(box.size());
    if (clen < crypto_secretbox_MACBYTES) {
        d_logger->error("kem_decrypt: ciphertext too short");
        sodium_memzero(ss.data(), ss.size());
        return;
    }
    const unsigned long long mlen = clen - crypto_secretbox_MACBYTES;
    if (mlen > crypto_secretbox_MESSAGEBYTES_MAX) {
        d_logger->error("kem_decrypt: message length out of range");
        sodium_memzero(ss.data(), ss.size());
        return;
    }

    std::vector<uint8_t> plaintext(static_cast<size_t>(mlen));
    if (crypto_secretbox_open_easy(plaintext.data(),
                                   box.data(),
                                   clen,
                                   nonce.data(),
                                   ss.data()) != 0) {
        d_logger->error("kem_decrypt: crypto_secretbox_open_easy failed");
        sodium_memzero(ss.data(), ss.size());
        return;
    }
    sodium_memzero(ss.data(), ss.size());

    message_port_pub(pmt::mp("out"), pmt::init_u8vector(plaintext.size(), plaintext));
}

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_SODIUM

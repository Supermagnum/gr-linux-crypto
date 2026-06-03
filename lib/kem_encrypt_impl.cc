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

#include "kem_encrypt_impl.h"
#include <gnuradio/io_signature.h>
#include <pmt/pmt.h>
#include <sodium.h>
#include <fstream>
#include <stdexcept>

namespace gr {
namespace linux_crypto {

namespace kem_pdu {

void append_u32_be(std::vector<uint8_t>& out, uint32_t v)
{
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(v & 0xff));
}

bool read_u32_be(const std::vector<uint8_t>& in, size_t& off, uint32_t& v)
{
    if (off + 4 > in.size()) {
        return false;
    }
    v = (static_cast<uint32_t>(in[off]) << 24) |
        (static_cast<uint32_t>(in[off + 1]) << 16) |
        (static_cast<uint32_t>(in[off + 2]) << 8) |
        static_cast<uint32_t>(in[off + 3]);
    off += 4;
    return true;
}

std::vector<uint8_t> pack(const std::vector<uint8_t>& kem_ct,
                            const std::vector<uint8_t>& nonce,
                            const std::vector<uint8_t>& box)
{
    std::vector<uint8_t> out;
    out.insert(out.end(), MAGIC, MAGIC + 4);
    append_u32_be(out, static_cast<uint32_t>(kem_ct.size()));
    out.insert(out.end(), kem_ct.begin(), kem_ct.end());
    append_u32_be(out, static_cast<uint32_t>(nonce.size()));
    out.insert(out.end(), nonce.begin(), nonce.end());
    append_u32_be(out, static_cast<uint32_t>(box.size()));
    out.insert(out.end(), box.begin(), box.end());
    return out;
}

bool unpack(const std::vector<uint8_t>& in,
            std::vector<uint8_t>& kem_ct,
            std::vector<uint8_t>& nonce,
            std::vector<uint8_t>& box)
{
    if (in.size() < 16) {
        return false;
    }
    if (in[0] != MAGIC[0] || in[1] != MAGIC[1] || in[2] != MAGIC[2] || in[3] != MAGIC[3]) {
        return false;
    }
    size_t off = 4;
    uint32_t kem_len = 0;
    uint32_t nonce_len = 0;
    uint32_t box_len = 0;
    if (!read_u32_be(in, off, kem_len) || kem_len != crypto_kem_CIPHERTEXTBYTES) {
        return false;
    }
    if (off + kem_len > in.size()) {
        return false;
    }
    kem_ct.assign(in.begin() + static_cast<std::ptrdiff_t>(off),
                  in.begin() + static_cast<std::ptrdiff_t>(off + kem_len));
    off += kem_len;
    if (!read_u32_be(in, off, nonce_len) || nonce_len != crypto_secretbox_NONCEBYTES) {
        return false;
    }
    if (off + nonce_len > in.size()) {
        return false;
    }
    nonce.assign(in.begin() + static_cast<std::ptrdiff_t>(off),
                 in.begin() + static_cast<std::ptrdiff_t>(off + nonce_len));
    off += nonce_len;
    if (!read_u32_be(in, off, box_len) || box_len == 0) {
        return false;
    }
    if (off + box_len > in.size()) {
        return false;
    }
    box.assign(in.begin() + static_cast<std::ptrdiff_t>(off),
               in.begin() + static_cast<std::ptrdiff_t>(off + box_len));
    return true;
}

} // namespace kem_pdu

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
    throw std::runtime_error("kem_encrypt: expected u8vector or blob PDU");
}

kem_encrypt::sptr kem_encrypt::make(const std::string& public_key_file)
{
    return gnuradio::get_initial_sptr(new kem_encrypt_impl(public_key_file));
}

kem_encrypt_impl::kem_encrypt_impl(const std::string& public_key_file)
    : gr::block("kem_encrypt",
                gr::io_signature::make(0, 0, 0),
                gr::io_signature::make(0, 0, 0)),
      d_public_key_file(public_key_file)
{
    if (sodium_init() < 0) {
        throw std::runtime_error("kem_encrypt: sodium_init failed");
    }
    message_port_register_in(pmt::mp("in"));
    message_port_register_out(pmt::mp("out"));
    set_msg_handler(pmt::mp("in"), [this](pmt::pmt_t msg) { handle_pdu(msg); });
    if (!reload_public_key()) {
        throw std::runtime_error("kem_encrypt: failed to load public key from " +
                                 public_key_file);
    }
}

kem_encrypt_impl::~kem_encrypt_impl() = default;

bool kem_encrypt_impl::reload_public_key()
{
    std::lock_guard<std::mutex> lock(d_mutex);
    if (d_public_key_file.empty()) {
        return false;
    }
    std::ifstream in(d_public_key_file, std::ios::binary);
    if (!in) {
        return false;
    }
    d_public_key.resize(crypto_kem_PUBLICKEYBYTES);
    in.read(reinterpret_cast<char*>(d_public_key.data()),
            static_cast<std::streamsize>(d_public_key.size()));
    return in.gcount() == static_cast<std::streamsize>(d_public_key.size());
}

void kem_encrypt_impl::set_public_key_file(const std::string& path)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    d_public_key_file = path;
    if (!reload_public_key()) {
        throw std::runtime_error("kem_encrypt: failed to load public key from " + path);
    }
}

std::string kem_encrypt_impl::public_key_file() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_public_key_file;
}

void kem_encrypt_impl::handle_pdu(pmt::pmt_t msg)
{
    std::vector<uint8_t> plaintext;
    try {
        plaintext = pmt_to_bytes(msg);
    } catch (const std::exception& e) {
        d_logger->error("{:s}", e.what());
        return;
    }

    if (plaintext.size() > crypto_secretbox_MESSAGEBYTES_MAX) {
        d_logger->error("kem_encrypt: plaintext too long ({:d} bytes)", plaintext.size());
        return;
    }

    std::vector<uint8_t> pk;
    {
        std::lock_guard<std::mutex> lock(d_mutex);
        pk = d_public_key;
    }
    if (pk.size() != crypto_kem_PUBLICKEYBYTES) {
        d_logger->error("kem_encrypt: invalid public key size");
        return;
    }

    std::vector<uint8_t> kem_ct(crypto_kem_CIPHERTEXTBYTES);
    std::vector<uint8_t> ss(crypto_kem_SHAREDSECRETBYTES);
    if (crypto_kem_enc(kem_ct.data(), ss.data(), pk.data()) != 0) {
        d_logger->error("kem_encrypt: crypto_kem_enc failed");
        sodium_memzero(ss.data(), ss.size());
        return;
    }

    std::vector<uint8_t> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    const unsigned long long mlen = static_cast<unsigned long long>(plaintext.size());
    std::vector<uint8_t> box(static_cast<size_t>(mlen + crypto_secretbox_MACBYTES));
    if (crypto_secretbox_easy(box.data(),
                              plaintext.data(),
                              mlen,
                              nonce.data(),
                              ss.data()) != 0) {
        d_logger->error("kem_encrypt: crypto_secretbox_easy failed");
        sodium_memzero(ss.data(), ss.size());
        return;
    }
    sodium_memzero(ss.data(), ss.size());

    const std::vector<uint8_t> out = kem_pdu::pack(kem_ct, nonce, box);
    message_port_pub(pmt::mp("out"), pmt::init_u8vector(out.size(), out));
}

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_SODIUM

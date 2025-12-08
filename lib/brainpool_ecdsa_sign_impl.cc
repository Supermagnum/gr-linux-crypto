/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * gr-linux-crypto is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * gr-linux-crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gr-linux-crypto; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_OPENSSL

#include <gnuradio/io_signature.h>
#include "brainpool_ecdsa_sign_impl.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <cstring>
#include <stdexcept>
#include <algorithm>

namespace gr {
namespace linux_crypto {

brainpool_ecdsa_sign::sptr
brainpool_ecdsa_sign::make(const std::string& curve,
                          const std::string& private_key_pem,
                          const std::string& hash_algorithm)
{
    return gnuradio::get_initial_sptr(
        new brainpool_ecdsa_sign_impl(curve, private_key_pem, hash_algorithm));
}

brainpool_ecdsa_sign_impl::brainpool_ecdsa_sign_impl(
    const std::string& curve,
    const std::string& private_key_pem,
    const std::string& hash_algorithm)
    : gr::sync_block("brainpool_ecdsa_sign",
                     gr::io_signature::make(1, 1, sizeof(unsigned char)),
                     gr::io_signature::make(1, 1, sizeof(unsigned char))),
      d_curve(brainpool_ec_impl::string_to_curve(curve)),
      d_curve_name(curve),
      d_hash_algorithm(hash_algorithm),
      d_brainpool_ec(std::make_shared<brainpool_ec_impl>(d_curve)),
      d_private_key(nullptr)
{
    if (!private_key_pem.empty()) {
        set_private_key(private_key_pem);
    }
    
    size_t max_sig_size = get_max_signature_size();
    set_output_multiple(max_sig_size + 1);
}

brainpool_ecdsa_sign_impl::~brainpool_ecdsa_sign_impl()
{
    std::lock_guard<std::mutex> lock(d_mutex);
    if (d_private_key) {
        EVP_PKEY_free(d_private_key);
        d_private_key = nullptr;
    }
}

size_t
brainpool_ecdsa_sign_impl::get_max_signature_size() const
{
    switch (d_curve) {
        case brainpool_ec_impl::Curve::BRAINPOOLP256R1:
            return 72;
        case brainpool_ec_impl::Curve::BRAINPOOLP384R1:
            return 104;
        case brainpool_ec_impl::Curve::BRAINPOOLP512R1:
            return 136;
        default:
            return 72;
    }
}

const EVP_MD*
brainpool_ecdsa_sign_impl::get_hash_function() const
{
    if (d_hash_algorithm == "sha256") {
        return EVP_sha256();
    } else if (d_hash_algorithm == "sha384") {
        return EVP_sha384();
    } else if (d_hash_algorithm == "sha512") {
        return EVP_sha512();
    }
    return EVP_sha256();
}

void
brainpool_ecdsa_sign_impl::set_private_key(const std::string& private_key_pem)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (d_private_key) {
        EVP_PKEY_free(d_private_key);
        d_private_key = nullptr;
    }
    
    if (private_key_pem.empty()) {
        return;
    }
    
    BIO* bio = BIO_new_mem_buf(private_key_pem.data(), private_key_pem.size());
    if (!bio) {
        return;
    }
    
    d_private_key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
}

std::string
brainpool_ecdsa_sign_impl::get_private_key() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (!d_private_key) {
        return "";
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return "";
    }
    
    if (PEM_write_bio_PrivateKey(bio, d_private_key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        return "";
    }
    
    char* pem_ptr = nullptr;
    long pem_len = BIO_get_mem_data(bio, &pem_ptr);
    std::string result;
    if (pem_len > 0 && pem_ptr) {
        result.assign(pem_ptr, pem_len);
    }
    
    BIO_free(bio);
    return result;
}

void
brainpool_ecdsa_sign_impl::set_hash_algorithm(const std::string& hash_algorithm)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    if (hash_algorithm == "sha256" || hash_algorithm == "sha384" || hash_algorithm == "sha512") {
        d_hash_algorithm = hash_algorithm;
    }
}

std::string
brainpool_ecdsa_sign_impl::get_hash_algorithm() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_hash_algorithm;
}

std::string
brainpool_ecdsa_sign_impl::get_curve() const
{
    return d_curve_name;
}

bool
brainpool_ecdsa_sign_impl::sign_data(const uint8_t* data,
                                    size_t data_len,
                                    std::vector<uint8_t>& signature)
{
    if (!d_private_key) {
        return false;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return false;
    }
    
    const EVP_MD* md = get_hash_function();
    if (EVP_DigestSignInit(ctx, nullptr, md, nullptr, d_private_key) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    if (EVP_DigestSignUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    signature.resize(sig_len);
    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    EVP_MD_CTX_free(ctx);
    return true;
}

int
brainpool_ecdsa_sign_impl::work(int noutput_items,
                               gr_vector_const_void_star& input_items,
                               gr_vector_void_star& output_items)
{
    const unsigned char* in = (const unsigned char*)input_items[0];
    unsigned char* out = (unsigned char*)output_items[0];
    
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (!d_private_key) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    size_t max_sig_size = get_max_signature_size();
    size_t processed = 0;
    size_t output_pos = 0;
    
    constexpr size_t MAX_CHUNK_SIZE = 1024;
    
    while (processed < static_cast<size_t>(noutput_items) && 
           output_pos + max_sig_size < static_cast<size_t>(noutput_items)) {
        
        size_t available_input = static_cast<size_t>(noutput_items) - processed;
        size_t available_output = static_cast<size_t>(noutput_items) - output_pos;
        
        size_t chunk_size = std::min(available_input, MAX_CHUNK_SIZE);
        if (chunk_size == 0) {
            break;
        }
        
        std::vector<uint8_t> signature;
        if (!sign_data(in + processed, chunk_size, signature)) {
            memset(out + output_pos, 0, available_output);
            break;
        }
        
        size_t total_output_size = chunk_size + signature.size();
        if (output_pos + total_output_size > static_cast<size_t>(noutput_items)) {
            break;
        }
        
        std::memcpy(out + output_pos, in + processed, chunk_size);
        output_pos += chunk_size;
        
        std::memcpy(out + output_pos, signature.data(), signature.size());
        output_pos += signature.size();
        
        processed += chunk_size;
    }
    
    if (processed == 0) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    return output_pos;
}

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_OPENSSL


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
#include "brainpool_ecdsa_verify_impl.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <cstring>
#include <stdexcept>
#include <algorithm>

namespace gr {
namespace linux_crypto {

brainpool_ecdsa_verify::sptr
brainpool_ecdsa_verify::make(const std::string& curve,
                            const std::string& public_key_pem,
                            const std::string& hash_algorithm)
{
    return gnuradio::get_initial_sptr(
        new brainpool_ecdsa_verify_impl(curve, public_key_pem, hash_algorithm));
}

brainpool_ecdsa_verify_impl::brainpool_ecdsa_verify_impl(
    const std::string& curve,
    const std::string& public_key_pem,
    const std::string& hash_algorithm)
    : gr::sync_block("brainpool_ecdsa_verify",
                     gr::io_signature::make(1, 1, sizeof(unsigned char)),
                     gr::io_signature::make(1, 1, sizeof(unsigned char))),
      d_curve(brainpool_ec_impl::string_to_curve(curve)),
      d_curve_name(curve),
      d_hash_algorithm(hash_algorithm),
      d_brainpool_ec(std::make_shared<brainpool_ec_impl>(d_curve)),
      d_public_key(nullptr),
      d_max_signature_size(get_max_signature_size())
{
    if (!public_key_pem.empty()) {
        set_public_key(public_key_pem);
    }
}

brainpool_ecdsa_verify_impl::~brainpool_ecdsa_verify_impl()
{
    std::lock_guard<std::mutex> lock(d_mutex);
    if (d_public_key) {
        EVP_PKEY_free(d_public_key);
        d_public_key = nullptr;
    }
}

size_t
brainpool_ecdsa_verify_impl::get_max_signature_size() const
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
brainpool_ecdsa_verify_impl::get_hash_function() const
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
brainpool_ecdsa_verify_impl::set_public_key(const std::string& public_key_pem)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (d_public_key) {
        EVP_PKEY_free(d_public_key);
        d_public_key = nullptr;
    }
    
    if (public_key_pem.empty()) {
        return;
    }
    
    BIO* bio = BIO_new_mem_buf(public_key_pem.data(), public_key_pem.size());
    if (!bio) {
        return;
    }
    
    d_public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
}

std::string
brainpool_ecdsa_verify_impl::get_public_key() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (!d_public_key) {
        return "";
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return "";
    }
    
    if (PEM_write_bio_PUBKEY(bio, d_public_key) != 1) {
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
brainpool_ecdsa_verify_impl::set_hash_algorithm(const std::string& hash_algorithm)
{
    std::lock_guard<std::mutex> lock(d_mutex);
    if (hash_algorithm == "sha256" || hash_algorithm == "sha384" || hash_algorithm == "sha512") {
        d_hash_algorithm = hash_algorithm;
        d_max_signature_size = get_max_signature_size();
    }
}

std::string
brainpool_ecdsa_verify_impl::get_hash_algorithm() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_hash_algorithm;
}

std::string
brainpool_ecdsa_verify_impl::get_curve() const
{
    return d_curve_name;
}

bool
brainpool_ecdsa_verify_impl::verify_signature(const uint8_t* data,
                                             size_t data_len,
                                             const uint8_t* signature,
                                             size_t signature_len)
{
    if (!d_public_key) {
        return false;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return false;
    }
    
    const EVP_MD* md = get_hash_function();
    if (EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, d_public_key) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    int result = EVP_DigestVerifyFinal(ctx, signature, signature_len);
    EVP_MD_CTX_free(ctx);
    
    return (result == 1);
}

int
brainpool_ecdsa_verify_impl::work(int noutput_items,
                                 gr_vector_const_void_star& input_items,
                                 gr_vector_void_star& output_items)
{
    const unsigned char* in = (const unsigned char*)input_items[0];
    unsigned char* out = (unsigned char*)output_items[0];
    
    std::lock_guard<std::mutex> lock(d_mutex);
    
    if (!d_public_key) {
        memset(out, 0, noutput_items);
        return 0;
    }
    
    size_t processed = 0;
    size_t output_pos = 0;
    
    constexpr size_t MIN_CHUNK_SIZE = 64;
    
    while (processed + d_max_signature_size <= static_cast<size_t>(noutput_items) &&
           output_pos < static_cast<size_t>(noutput_items)) {
        
        size_t remaining = static_cast<size_t>(noutput_items) - processed;
        
        if (remaining < MIN_CHUNK_SIZE + d_max_signature_size) {
            break;
        }
        
        size_t chunk_size = remaining - d_max_signature_size;
        if (chunk_size == 0) {
            break;
        }
        
        const uint8_t* data = in + processed;
        const uint8_t* signature = in + processed + chunk_size;
        size_t sig_len = remaining - chunk_size;
        
        if (sig_len > d_max_signature_size) {
            sig_len = d_max_signature_size;
        }
        
        bool is_valid = verify_signature(data, chunk_size, signature, sig_len);
        
        if (is_valid) {
            std::memcpy(out + output_pos, data, chunk_size);
            output_pos += chunk_size;
        } else {
            memset(out + output_pos, 0, chunk_size);
            output_pos += chunk_size;
        }
        
        processed += chunk_size + sig_len;
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


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

#ifndef INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_DECRYPT_IMPL_H
#define INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_DECRYPT_IMPL_H

#ifdef HAVE_OPENSSL

#include <gnuradio/linux_crypto/brainpool_ecies_decrypt.h>
#include <gnuradio/io_signature.h>
#include <gnuradio/linux_crypto/brainpool_ec_impl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <vector>
#include <mutex>
#include <string>
#include <memory>

namespace gr {
namespace linux_crypto {

class brainpool_ecies_decrypt_impl : public brainpool_ecies_decrypt
{
private:
    brainpool_ec_impl::Curve d_curve;
    std::string d_curve_name;
    std::string d_kdf_info;
    std::shared_ptr<brainpool_ec_impl> d_brainpool_ec;
    
    EVP_PKEY* d_recipient_private_key;
    mutable std::mutex d_mutex;
    
    std::vector<uint8_t> d_input_buffer;
    std::vector<uint8_t> d_output_buffer;
    
    static constexpr size_t AES_KEY_SIZE = 32;
    static constexpr size_t AES_IV_SIZE = 12;
    static constexpr size_t AES_TAG_SIZE = 16;
    
    size_t d_ephemeral_public_key_size;
    bool d_key_loaded;
    
    bool derive_key_hkdf(const std::vector<uint8_t>& shared_secret,
                        std::vector<uint8_t>& key,
                        std::vector<uint8_t>& iv);
    
    bool decrypt_aes_gcm(const uint8_t* ciphertext,
                        size_t ciphertext_len,
                        const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv,
                        const std::vector<uint8_t>& tag,
                        std::vector<uint8_t>& plaintext);
    
    EVP_PKEY* deserialize_ephemeral_public_key(const uint8_t* data, size_t data_len);
    
    size_t get_public_key_size() const;

public:
    brainpool_ecies_decrypt_impl(const std::string& curve,
                                 const std::string& recipient_private_key_pem,
                                 const std::string& private_key_password,
                                 const std::string& kdf_info);
    ~brainpool_ecies_decrypt_impl();

    void set_recipient_private_key(const std::string& private_key_pem,
                                  const std::string& password) override;
    bool is_private_key_loaded() const override;
    void set_kdf_info(const std::string& kdf_info) override;
    std::string get_kdf_info() const override;
    std::string get_curve() const override;

    int work(int noutput_items,
             gr_vector_const_void_star& input_items,
             gr_vector_void_star& output_items) override;
};

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_OPENSSL

#endif /* INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECIES_DECRYPT_IMPL_H */


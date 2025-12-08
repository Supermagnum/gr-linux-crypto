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

#ifndef INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECDSA_SIGN_IMPL_H
#define INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECDSA_SIGN_IMPL_H

#ifdef HAVE_OPENSSL

#include <gnuradio/linux_crypto/brainpool_ecdsa_sign.h>
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

class brainpool_ecdsa_sign_impl : public brainpool_ecdsa_sign
{
private:
    brainpool_ec_impl::Curve d_curve;
    std::string d_curve_name;
    std::string d_hash_algorithm;
    std::shared_ptr<brainpool_ec_impl> d_brainpool_ec;
    
    EVP_PKEY* d_private_key;
    mutable std::mutex d_mutex;
    
    std::vector<uint8_t> d_input_buffer;
    std::vector<uint8_t> d_output_buffer;
    
    const EVP_MD* get_hash_function() const;
    size_t get_max_signature_size() const;
    bool sign_data(const uint8_t* data,
                  size_t data_len,
                  std::vector<uint8_t>& signature);

public:
    brainpool_ecdsa_sign_impl(const std::string& curve,
                              const std::string& private_key_pem,
                              const std::string& hash_algorithm);
    ~brainpool_ecdsa_sign_impl();

    void set_private_key(const std::string& private_key_pem) override;
    std::string get_private_key() const override;
    void set_hash_algorithm(const std::string& hash_algorithm) override;
    std::string get_hash_algorithm() const override;
    std::string get_curve() const override;

    int work(int noutput_items,
             gr_vector_const_void_star& input_items,
             gr_vector_void_star& output_items) override;
};

} // namespace linux_crypto
} // namespace gr

#endif // HAVE_OPENSSL

#endif /* INCLUDED_GR_LINUX_CRYPTO_BRAINPOOL_ECDSA_SIGN_IMPL_H */


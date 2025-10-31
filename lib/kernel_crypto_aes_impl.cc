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

#include <gnuradio/io_signature.h>
#include "kernel_crypto_aes_impl.h"
#include <cstring>
#include <stdexcept>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <sys/uio.h>

namespace gr {
namespace linux_crypto {

/**
 * @brief Create a kernel crypto AES block
 * @param key The AES key (16, 24, or 32 bytes for AES-128, AES-192, AES-256)
 * @param iv The initialization vector (16 bytes for AES)
 * @param mode The AES mode ("cbc", "ecb", "ctr", "gcm")
 * @param encrypt Whether to encrypt (true) or decrypt (false)
 * @return Shared pointer to the kernel crypto AES block
 */
kernel_crypto_aes::sptr
kernel_crypto_aes::make(const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv,
                        const std::string& mode,
                        bool encrypt)
{
    return gnuradio::get_initial_sptr(
        new kernel_crypto_aes_impl(key, iv, mode, encrypt));
}

kernel_crypto_aes_impl::kernel_crypto_aes_impl(const std::vector<unsigned char>& key,
                                               const std::vector<unsigned char>& iv,
                                               const std::string& mode,
                                               bool encrypt)
    : gr::sync_block("kernel_crypto_aes",
                     gr::io_signature::make(1, 1, sizeof(unsigned char)),
                     gr::io_signature::make(1, 1, sizeof(unsigned char))),
      d_key(key),
      d_iv(iv),
      d_mode(mode),
      d_encrypt(encrypt),
      d_kernel_crypto_available(false),
      d_socket_fd(-1),
      d_accept_fd(-1)
{
    // Validate key size
    if (d_key.size() != 16 && d_key.size() != 24 && d_key.size() != 32) {
        d_kernel_crypto_available = false;
        return;
    }

    // Validate mode string
    if (d_mode != "cbc" && d_mode != "ecb" && d_mode != "ctr" && d_mode != "gcm") {
        d_kernel_crypto_available = false;
        return;
    }

    // Validate IV size for modes that require it
    if (d_mode == "cbc" || d_mode == "ctr" || d_mode == "gcm") {
        if (d_iv.size() != 16) {  // AES block size
            d_kernel_crypto_available = false;
            return;
        }
    }

    connect_to_kernel_crypto();
}

kernel_crypto_aes_impl::~kernel_crypto_aes_impl()
{
    disconnect_from_kernel_crypto();
}

void
kernel_crypto_aes_impl::connect_to_kernel_crypto()
{
    std::lock_guard<std::mutex> lock(d_mutex);

    // Create AF_ALG socket
    d_socket_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (d_socket_fd < 0) {
        d_kernel_crypto_available = false;
        return;
    }

    // Set up algorithm
    struct sockaddr_alg sa = {};
    sa.salg_family = AF_ALG;
    // Use memcpy for fixed-size buffers to avoid strncpy null-termination issues
    const std::string alg_type = "skcipher";
    const std::string alg_name = "aes-" + d_mode;
    memcpy(sa.salg_type, alg_type.c_str(), std::min(alg_type.size(), sizeof(sa.salg_type) - 1));
    sa.salg_type[sizeof(sa.salg_type) - 1] = '\0';
    memcpy(sa.salg_name, alg_name.c_str(), std::min(alg_name.size(), sizeof(sa.salg_name) - 1));
    sa.salg_name[sizeof(sa.salg_name) - 1] = '\0';

    if (bind(d_socket_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(d_socket_fd);
        d_socket_fd = -1;
        d_kernel_crypto_available = false;
        return;
    }

    // Accept connection
    d_accept_fd = accept(d_socket_fd, nullptr, nullptr);
    if (d_accept_fd < 0) {
        close(d_socket_fd);
        d_socket_fd = -1;
        d_kernel_crypto_available = false;
        return;
    }

    // Set key
    if (setsockopt(d_accept_fd, SOL_ALG, ALG_SET_KEY, d_key.data(), d_key.size()) < 0) {
        close(d_accept_fd);
        close(d_socket_fd);
        d_accept_fd = -1;
        d_socket_fd = -1;
        d_kernel_crypto_available = false;
        return;
    }

    d_kernel_crypto_available = true;
}

void
kernel_crypto_aes_impl::disconnect_from_kernel_crypto()
{
    std::lock_guard<std::mutex> lock(d_mutex);

    if (d_accept_fd >= 0) {
        close(d_accept_fd);
        d_accept_fd = -1;
    }

    if (d_socket_fd >= 0) {
        close(d_socket_fd);
        d_socket_fd = -1;
    }

    d_kernel_crypto_available = false;
}

bool
kernel_crypto_aes_impl::is_kernel_crypto_available() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_kernel_crypto_available;
}

std::vector<unsigned char>
kernel_crypto_aes_impl::get_key() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_key;
}

std::vector<unsigned char>
kernel_crypto_aes_impl::get_iv() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_iv;
}

std::string
kernel_crypto_aes_impl::get_mode() const
{
    return d_mode;
}

bool
kernel_crypto_aes_impl::is_encrypt() const
{
    return d_encrypt;
}

void
kernel_crypto_aes_impl::set_key(const std::vector<unsigned char>& key)
{
    std::lock_guard<std::mutex> lock(d_mutex);

    // Validate key size
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        return;
    }

    d_key = key;

    if (d_kernel_crypto_available && d_accept_fd >= 0) {
        if (setsockopt(d_accept_fd, SOL_ALG, ALG_SET_KEY, d_key.data(), d_key.size()) < 0) {
            d_kernel_crypto_available = false;
        }
    }
}

void
kernel_crypto_aes_impl::set_iv(const std::vector<unsigned char>& iv)
{
    std::lock_guard<std::mutex> lock(d_mutex);

    // Validate IV size for modes that require it
    if (d_mode == "cbc" || d_mode == "ctr" || d_mode == "gcm") {
        if (iv.size() != 16) {  // AES block size
            return;
        }
    }

    d_iv = iv;
}

void
kernel_crypto_aes_impl::set_mode(const std::string& mode)
{
    // Validate mode string
    if (mode != "cbc" && mode != "ecb" && mode != "ctr" && mode != "gcm") {
        return;
    }

    std::lock_guard<std::mutex> lock(d_mutex);
    d_mode = mode;
    disconnect_from_kernel_crypto();
    connect_to_kernel_crypto();
}

void
kernel_crypto_aes_impl::set_encrypt(bool encrypt)
{
    d_encrypt = encrypt;
}

std::vector<std::string>
kernel_crypto_aes_impl::get_supported_modes() const
{
    return {"cbc", "ecb", "ctr", "gcm"};
}

std::vector<int>
kernel_crypto_aes_impl::get_supported_key_sizes() const
{
    return {16, 24, 32};  // AES-128, AES-192, AES-256
}

int
kernel_crypto_aes_impl::work(int noutput_items,
                            gr_vector_const_void_star& input_items,
                            gr_vector_void_star& output_items)
{
    const unsigned char* in = (const unsigned char*)input_items[0];
    unsigned char* out = (unsigned char*)output_items[0];

    if (!d_kernel_crypto_available) {
        // Kernel crypto not available - output zeros rather than leaking plaintext
        memset(out, 0, noutput_items);
        return 0;
    }

    process_data(in, out, noutput_items);
    return noutput_items;
}

void
kernel_crypto_aes_impl::process_data(const unsigned char* input, unsigned char* output, int n_items)
{
    if (d_accept_fd < 0 || n_items <= 0) {
        return;
    }

    // Prepare message for AF_ALG socket
    struct msghdr msg = {};
    struct iovec iov = {};
    
    // Allocate buffer for control message (IV)
    char cbuf[CMSG_SPACE(sizeof(struct af_alg_iv))];
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    
    // Set up IV for modes that require it (CBC, CTR, GCM)
    if (!d_iv.empty() && (d_mode == "cbc" || d_mode == "ctr" || d_mode == "gcm")) {
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_IV;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv));
        
        struct af_alg_iv* alg_iv = (struct af_alg_iv*)CMSG_DATA(cmsg);
        alg_iv->ivlen = d_iv.size();
        memcpy(alg_iv->iv, d_iv.data(), d_iv.size());
    }
    
    // Set up data vector
    iov.iov_base = const_cast<unsigned char*>(input);
    iov.iov_len = n_items;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    // Send data to kernel crypto API
    // AF_ALG sockets handle both encrypt and decrypt based on the socket state
    if (sendmsg(d_accept_fd, &msg, 0) < 0) {
        // On error, clear output rather than leaking plaintext
        memset(output, 0, n_items);
        return;
    }
    
    // Receive encrypted/decrypted data from kernel
    ssize_t received = recv(d_accept_fd, output, n_items, 0);
    if (received < 0) {
        // On error, clear output rather than leaking plaintext
        memset(output, 0, n_items);
        return;
    }
    
    // Ensure we got the expected amount
    // AF_ALG sockets should return exactly the amount sent, but handle partial receives
    if (static_cast<int>(received) != n_items) {
        // Partial receive indicates an error - clear output
        memset(output, 0, n_items);
        return;
    }
}

} // namespace linux_crypto
} // namespace gr

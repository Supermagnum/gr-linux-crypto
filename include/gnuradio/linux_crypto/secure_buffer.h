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
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * SecureBuffer: RAII buffer that zeroizes memory on destruction (BSZ AIS-B2).
 */

#ifndef INCLUDED_GR_LINUX_CRYPTO_SECURE_BUFFER_H
#define INCLUDED_GR_LINUX_CRYPTO_SECURE_BUFFER_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
#endif

namespace gr {
namespace linux_crypto {

/*!
 * \brief RAII buffer that securely zeroizes memory on destruction.
 *
 * Use for session keys, shared secrets, and other sensitive material.
 * On destruction, memory is cleared via OPENSSL_cleanse() when OpenSSL
 * is available, otherwise a compiler-barrier-protected volatile write.
 */
class secure_buffer
{
public:
    secure_buffer() = default;
    explicit secure_buffer(size_t n) : d_data(n) {}
    secure_buffer(const secure_buffer&) = delete;
    secure_buffer& operator=(const secure_buffer&) = delete;
    secure_buffer(secure_buffer&& other) noexcept : d_data(std::move(other.d_data))
    {
        other.d_data.clear();
    }
    secure_buffer& operator=(secure_buffer&& other) noexcept
    {
        secure_clear();
        d_data = std::move(other.d_data);
        other.d_data.clear();
        return *this;
    }

    ~secure_buffer() { secure_clear(); }

    void resize(size_t n)
    {
        secure_clear();
        d_data.resize(n);
    }

    void clear()
    {
        secure_clear();
        d_data.clear();
    }

    unsigned char* data() { return d_data.empty() ? nullptr : d_data.data(); }
    const unsigned char* data() const
    {
        return d_data.empty() ? nullptr : d_data.data();
    }
    size_t size() const { return d_data.size(); }
    bool empty() const { return d_data.empty(); }

    std::vector<unsigned char>& vec() { return d_data; }
    const std::vector<unsigned char>& vec() const { return d_data; }

private:
    std::vector<unsigned char> d_data;

    void secure_clear()
    {
        if (d_data.empty())
            return;
#ifdef HAVE_OPENSSL
        OPENSSL_cleanse(d_data.data(), d_data.size());
#else
        volatile unsigned char* p = d_data.data();
        size_t n = d_data.size();
        while (n--)
            *p++ = 0;
#endif
    }
};

/*!
 * \brief Securely zeroize and clear a vector (e.g. key material).
 */
inline void secure_clear(std::vector<unsigned char>& v)
{
    if (v.empty())
        return;
#ifdef HAVE_OPENSSL
    OPENSSL_cleanse(v.data(), v.size());
#else
    volatile unsigned char* p = v.data();
    size_t n = v.size();
    while (n--)
        *p++ = 0;
#endif
    v.clear();
}

/*!
 * Overload for std::vector<uint8_t>. On typical platforms uint8_t is
 * unsigned char; if not, use secure_clear on a vector<unsigned char> or
 * cast. Avoids ODR issues when both vector<unsigned char> and vector<uint8_t>
 * are used.
 */
template <typename Byte>
inline typename std::enable_if<sizeof(Byte) == 1 && !std::is_same<Byte, unsigned char>::value, void>::type
secure_clear(std::vector<Byte>& v)
{
    if (v.empty())
        return;
#ifdef HAVE_OPENSSL
    OPENSSL_cleanse(v.data(), v.size());
#else
    volatile Byte* p = v.data();
    size_t n = v.size();
    while (n--)
        *p++ = 0;
#endif
    v.clear();
}

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_GR_LINUX_CRYPTO_SECURE_BUFFER_H */

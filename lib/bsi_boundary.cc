/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * BSI TR-02102 algorithm boundary runtime checks.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/linux_crypto/bsi_boundary.h>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace gr {
namespace linux_crypto {

static std::string to_lower(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

static std::string normalize(std::string s)
{
    s = to_lower(s);
    s.erase(std::remove_if(s.begin(), s.end(),
                          [](char c) { return c == '-' || c == '_' || c == ' '; }),
            s.end());
    return s;
}

#ifdef GR_LINUX_CRYPTO_STRICT_BSI

static const std::unordered_set<std::string> s_approved_curves = {
    "brainpoolp256r1",
    "brainpoolp384r1",
    "brainpoolp512r1",
};

static const std::unordered_set<std::string> s_approved_symmetric = {
    "aes128gcm",
    "aes256gcm",
    "chacha20poly1305",
};

static const std::unordered_set<std::string> s_approved_hash = {
    "sha256",
    "sha384",
    "sha512",
};

static const char* s_bsi_ref = "BSI TR-02102 (https://www.bsi.bund.de/tr02102)";

bool bsi_allow_curve(const std::string& curve)
{
    return s_approved_curves.count(normalize(curve)) != 0;
}

bool bsi_allow_symmetric(const std::string& cipher)
{
    return s_approved_symmetric.count(normalize(cipher)) != 0;
}

bool bsi_allow_hash(const std::string& hash)
{
    return s_approved_hash.count(normalize(hash)) != 0;
}

void bsi_require_curve(const std::string& curve)
{
    if (!bsi_allow_curve(curve)) {
        throw std::invalid_argument(
            "Curve not approved for use: '" + curve + "'. "
            "Only brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 are approved. "
            "See " + std::string(s_bsi_ref));
    }
}

void bsi_require_symmetric(const std::string& cipher)
{
    if (!bsi_allow_symmetric(cipher)) {
        throw std::invalid_argument(
            "Symmetric cipher not approved: '" + cipher + "'. "
            "Only AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 are approved. "
            "See " + std::string(s_bsi_ref));
    }
}

void bsi_require_hash(const std::string& hash)
{
    if (!bsi_allow_hash(hash)) {
        throw std::invalid_argument(
            "Hash algorithm not approved: '" + hash + "'. "
            "Only SHA-256, SHA-384, SHA-512 are approved. "
            "See " + std::string(s_bsi_ref));
    }
}

#else

bool bsi_allow_curve(const std::string&) { return true; }
bool bsi_allow_symmetric(const std::string&) { return true; }
bool bsi_allow_hash(const std::string&) { return true; }
void bsi_require_curve(const std::string&) {}
void bsi_require_symmetric(const std::string&) {}
void bsi_require_hash(const std::string&) {}

#endif /* GR_LINUX_CRYPTO_STRICT_BSI */

} // namespace linux_crypto
} // namespace gr

// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_DETAIL_BRAINPOOLHASH_HPP
#define GNURADIO4_LINUX_CRYPTO_DETAIL_BRAINPOOLHASH_HPP

#include <openssl/evp.h>

#include <string_view>

namespace gnuradio4::linux_crypto::detail {

[[nodiscard]] inline const EVP_MD* hashFromName(std::string_view name) {
    if (name == "sha384") {
        return EVP_sha384();
    }
    if (name == "sha512") {
        return EVP_sha512();
    }
    return EVP_sha256();
}

} // namespace gnuradio4::linux_crypto::detail

#endif

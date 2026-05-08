// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_DETAIL_ECiesCodec_HPP
#define GNURADIO4_LINUX_CRYPTO_DETAIL_ECiesCodec_HPP

/** @file Wire-compatible ECIES framing with gr-linux-crypto (brainpool + AES-256-GCM + HKDF-SHA256). */

#include <openssl/evp.h>

#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace gnuradio4::linux_crypto::detail {

constexpr std::size_t kEciesAesKey = 32U;
/** Wire format IV length (matches GR3 brainpool_ecies_* and Python multi_recipient_ecies AES-GCM). */
constexpr std::size_t kEciesIv = 12U;
constexpr std::size_t kEciesTag    = 16U;

[[nodiscard]] bool eciesEncryptPem(BrainpoolEcImpl& ec, EVP_PKEY* recipientPubkey, std::string_view kdfInfo, std::span<const std::uint8_t> plaintext,
    std::vector<std::uint8_t>& wire);

[[nodiscard]] bool eciesDecryptPem(EVP_PKEY* recipientPriv, std::string_view kdfInfo, std::span<const std::uint8_t> wire, std::vector<std::uint8_t>& plaintext);

[[nodiscard]] bool multiEncryptPem(const std::vector<EVP_PKEY*>& recipients, BrainpoolEcImpl& ec256, std::string_view kdfInfo,
    std::span<const std::uint8_t> plaintext, std::vector<std::uint8_t>& wire);

[[nodiscard]] bool multiDecryptTryKeys(const std::vector<EVP_PKEY*>& privateKeysCandidate, std::string_view kdfInfo, std::span<const std::uint8_t> wire,
    std::vector<std::uint8_t>& plaintext);

EVP_PKEY* loadPublicKeyFromPemString(std::string_view pem);
EVP_PKEY* loadPrivateKeyFromPemString(std::string_view pem);
void                      freeKeys(const std::vector<EVP_PKEY*>& keys);

} // namespace gnuradio4::linux_crypto::detail

#endif

// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_DETAIL_MULTIRECIPIENTECIES_HPP
#define GNURADIO4_LINUX_CRYPTO_DETAIL_MULTIRECIPIENTECIES_HPP

#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>
#include <gnuradio-4.0/linux_crypto/detail/CallsignKeyStore.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace gnuradio4::linux_crypto::detail {

/** Matches python/multi_recipient_ecies.py FORMAT_VERSION 0x01, cipher_id AES-GCM. */
constexpr std::size_t kMultiPayloadIv  = 12U;
constexpr std::size_t kMultiPayloadTag = 16U;
constexpr std::size_t kMultiSymKeyLen  = 32U;

[[nodiscard]] std::uint8_t curveToId(BrainpoolEcImpl::Curve c);

[[nodiscard]] bool multiRecipientEncrypt(BrainpoolEcImpl::Curve curve, const CallsignKeyStore& store, std::span<const std::string> recipients,
    std::string_view kdfInfo, std::span<const std::uint8_t> plaintext, std::vector<std::uint8_t>& wire);

[[nodiscard]] bool multiRecipientDecrypt(BrainpoolEcImpl::Curve curve, std::string_view recipientCallsignUpper, std::string_view privateKeyPem,
    std::string_view kdfInfo, std::span<const std::uint8_t> wire, std::vector<std::uint8_t>& plaintext);

} // namespace gnuradio4::linux_crypto::detail

#endif

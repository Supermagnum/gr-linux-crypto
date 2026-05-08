// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_DETAIL_KERNELKEYRING_DETAIL_HPP
#define GNURADIO4_LINUX_CRYPTO_DETAIL_KERNELKEYRING_DETAIL_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

namespace gnuradio4::linux_crypto::detail {

using KeySerialNative = std::int32_t;

[[nodiscard]] bool keyring_probe(KeySerialNative id) noexcept;
[[nodiscard]] bool keyring_read_payload(KeySerialNative id, std::vector<std::uint8_t>& out) noexcept;

} // namespace gnuradio4::linux_crypto::detail

#endif

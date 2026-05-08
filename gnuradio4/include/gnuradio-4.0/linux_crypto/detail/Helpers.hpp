// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_DETAIL_HELPERS_HPP
#define GNURADIO4_LINUX_CRYPTO_DETAIL_HELPERS_HPP

#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/Value.hpp>

#include <cstddef>
#include <memory_resource>
#include <optional>
#include <span>
#include <string_view>

namespace gnuradio4::linux_crypto::detail {

[[nodiscard]] inline const gr::Tensor<std::uint8_t>* tensorBytesFromMap(const gr::property_map& map, std::string_view keyView) {
    const std::pmr::string key(keyView.begin(), keyView.end());
    const auto              it = map.find(key);
    if (it == map.end()) {
        return nullptr;
    }
    return it->second.get_if<gr::Tensor<std::uint8_t>>();
}

[[nodiscard]] inline std::optional<gr::Size_t> readPduLength(const gr::property_map& map, std::string_view keyView) {
    const std::pmr::string key(keyView.begin(), keyView.end());
    const auto              it = map.find(key);
    if (it == map.end()) {
        return std::nullopt;
    }
    const gr::pmt::Value& v = it->second;
    if (const auto* p = v.get_if<std::uint64_t>()) {
        return static_cast<gr::Size_t>(*p);
    }
    if (const auto* p = v.get_if<std::int64_t>()) {
        return static_cast<gr::Size_t>(*p);
    }
    if (const auto* p = v.get_if<std::uint32_t>()) {
        return static_cast<gr::Size_t>(*p);
    }
    if (const auto* p = v.get_if<std::int32_t>()) {
        return static_cast<gr::Size_t>(*p);
    }
    return std::nullopt;
}

} // namespace gnuradio4::linux_crypto::detail

#endif

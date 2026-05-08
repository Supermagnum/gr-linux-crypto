// SPDX-License-Identifier: GPL-3.0-or-later

#include <gnuradio-4.0/linux_crypto/detail/KernelKeyringDetail.hpp>

#include <openssl/crypto.h>

#include <cstdint>
#include <cstdlib>

#if defined(__linux__)
#include <keyutils.h>

namespace gnuradio4::linux_crypto::detail {

bool keyring_probe(KeySerialNative rawId) noexcept {
    key_serial_t id      = static_cast<key_serial_t>(rawId);
    void*        payload = nullptr;
    const int    nbytes  = ::keyctl_read_alloc(id, &payload);
    if (nbytes <= 0) {
        return false;
    }
    OPENSSL_cleanse(payload, static_cast<std::size_t>(nbytes));
    std::free(payload);
    return true;
}

bool keyring_read_payload(KeySerialNative rawId, std::vector<std::uint8_t>& out) noexcept {
    out.clear();
    key_serial_t id      = static_cast<key_serial_t>(rawId);
    void*        payload = nullptr;
    const int    nbytes  = ::keyctl_read_alloc(id, &payload);
    if (nbytes <= 0 || payload == nullptr) {
        return false;
    }

    auto* pb = reinterpret_cast<const std::uint8_t*>(payload);
    out.assign(pb, pb + static_cast<std::size_t>(nbytes));
    OPENSSL_cleanse(payload, static_cast<std::size_t>(nbytes));
    std::free(payload);
    return true;
}

} // namespace gnuradio4::linux_crypto::detail

#else

namespace gnuradio4::linux_crypto::detail {

bool keyring_probe(KeySerialNative /*id*/) noexcept { return false; }

bool keyring_read_payload(KeySerialNative /*id*/, std::vector<std::uint8_t>& /*out*/) noexcept { return false; }

} // namespace gnuradio4::linux_crypto::detail

#endif

// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_DETAIL_AFALGAESCONTEXT_HPP
#define GNURADIO4_LINUX_CRYPTO_DETAIL_AFALGAESCONTEXT_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace gnuradio4::linux_crypto::detail {

/** Linux AF_ALG AES (skcipher) session; invalid on non-Linux (ok() == false). */
class AfalgAesContext {
public:
    AfalgAesContext() = default;
    AfalgAesContext(const AfalgAesContext&)            = delete;
    AfalgAesContext& operator=(const AfalgAesContext&) = delete;
    AfalgAesContext(AfalgAesContext&& other) noexcept;
    AfalgAesContext& operator=(AfalgAesContext&& other) noexcept;
    ~AfalgAesContext();

    [[nodiscard]] bool configured() const noexcept { return _configured; }

    /** Rebuild socket with given parameters. Cleans key material on failure. */
    bool setParams(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& iv, const std::string& mode, bool encrypt);

    void closeSockets() noexcept;

    /** Transform in->out; on failure closes AF_ALG and clears keyMirror (userland key copy). */
    bool transform(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, std::vector<std::uint8_t>& keyMirror) noexcept;

    /** Every ~1000 work calls; closes session and clears keyMirror if unhealthy. */
    void periodicHealthCheck(std::vector<std::uint8_t>& keyMirror) noexcept;

private:
    bool                 _configured = false;
    bool                 _encrypt    = true;
    std::string          _mode;
    std::vector<std::uint8_t> _iv;
    std::vector<std::uint8_t> _localKey{};
    int                    _sock  = -1;
    int                    _accfd = -1;
    unsigned               _heartbeat = 0U;

    bool bindSocket(const std::vector<std::uint8_t>& key);
    bool kernelTransform(std::span<const std::uint8_t> in, std::span<std::uint8_t> out) noexcept;
    bool unhealthy() noexcept;

    static void secureClearKeyMaterial(std::vector<std::uint8_t>& keyMaterial) noexcept;
};

} // namespace gnuradio4::linux_crypto::detail

#endif

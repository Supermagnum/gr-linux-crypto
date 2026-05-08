// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_KERNELCRYPTOAES_HPP
#define GNURADIO4_LINUX_CRYPTO_KERNELCRYPTOAES_HPP

#include <gnuradio-4.0/Block.hpp>
#include <gnuradio-4.0/BlockRegistry.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/annotated.hpp>
#include <gnuradio-4.0/meta/utils.hpp>

#include <gnuradio-4.0/linux_crypto/detail/AfalgAesContext.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>
#include <tuple>
#include <string>
#include <vector>

namespace gnuradio4::linux_crypto {

GR_REGISTER_BLOCK(gnuradio4::linux_crypto::KernelCryptoAes)

struct KernelCryptoAes : gr::Block<KernelCryptoAes> {
    using Description =
        gr::Doc<"AES encrypt/decrypt via Linux AF_ALG (kernel crypto). Periodic health checks rebuild the session when the socket breaks.">;

    gr::PortIn<std::uint8_t>  in{};
    gr::PortOut<std::uint8_t> out{};

    gr::Annotated<gr::Tensor<std::uint8_t>, "key", gr::Doc<"AES raw key bytes (16/24/32)">> key{};
    gr::Annotated<gr::Tensor<std::uint8_t>, "iv",
        gr::Doc<"AES IV (16 bytes) for CBC/CTR/GCM; leave empty for ECB">>                       iv{};
    gr::Annotated<std::string, "mode", gr::Doc<"cbc|ecb|ctr|gcm">>                                      mode{};
    gr::Annotated<bool, "encrypt", gr::Doc<"true encrypt, false decrypt">>                           aes_encrypt  = true;

    GR_MAKE_REFLECTABLE(KernelCryptoAes, in, out, key, iv, mode, aes_encrypt);

private:
    detail::AfalgAesContext   _sess{};
    std::vector<std::uint8_t> _keyScratch{};

public:
    void start() { applySettings(); }

    void stop() {
        _sess.closeSockets();
        if (!_keyScratch.empty()) {
            OPENSSL_cleanse(_keyScratch.data(), _keyScratch.size());
        }
        _keyScratch.clear();
    }

    void settingsChanged(const gr::property_map& /*old*/, const gr::property_map& ne) {
        if (ne.contains("key") || ne.contains("iv") || ne.contains("mode") || ne.contains("encrypt")) {
            applySettings();
        }
    }

    void applySettings() {
        std::vector<std::uint8_t> k(static_cast<std::vector<std::uint8_t>::size_type>(key.value.size()));
        std::copy(key.value.begin(), key.value.end(), k.begin());

        std::vector<std::uint8_t> v(static_cast<std::vector<std::uint8_t>::size_type>(iv.value.size()));
        std::copy(iv.value.begin(), iv.value.end(), v.begin());

        if (!_sess.setParams(k, v, mode.value, aes_encrypt.value)) [[unlikely]] {
            if (!_keyScratch.empty()) {
                OPENSSL_cleanse(_keyScratch.data(), _keyScratch.size());
            }
            _keyScratch.clear();
            this->requestStop();
            return;
        }

        if (!_keyScratch.empty()) {
            OPENSSL_cleanse(_keyScratch.data(), _keyScratch.size());
        }
        _keyScratch = std::move(k);
        if (!_sess.configured()) {
            this->requestStop();
        }
    }

    [[nodiscard]] gr::work::Status processBulk(std::span<const std::uint8_t>& ins, std::span<std::uint8_t>& outs) noexcept {
        _sess.periodicHealthCheck(_keyScratch);
        if (ins.empty() || outs.empty()) {
            outs.publish(0UZ);
            return gr::work::Status::INSUFFICIENT_INPUT_ITEMS;
        }
        const auto n = std::min(ins.size(), outs.size());
        if (!_sess.configured()) {
            if (n > 0UZ) {
                std::memset(outs.data(), 0, n);
            }
            outs.publish(n);
            std::ignore = ins.consume(n);
            return gr::work::Status::OK;
        }
        [[maybe_unused]] const bool ok = _sess.transform(ins.subspan(0UZ, n), outs.subspan(0UZ, n), _keyScratch);
        (void)ok;
        outs.publish(n);
        std::ignore = ins.consume(n);
        return gr::work::Status::OK;
    }
};

} // namespace gnuradio4::linux_crypto

#endif

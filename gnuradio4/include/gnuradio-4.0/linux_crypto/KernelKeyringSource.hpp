// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_KERNELKEYRINGSOURCE_HPP
#define GNURADIO4_LINUX_CRYPTO_KERNELKEYRINGSOURCE_HPP

#include <gnuradio-4.0/Block.hpp>
#include <gnuradio-4.0/BlockRegistry.hpp>
#include <gnuradio-4.0/annotated.hpp>
#include <gnuradio-4.0/meta/utils.hpp>

#include <gnuradio-4.0/linux_crypto/detail/KernelKeyringDetail.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace gnuradio4::linux_crypto {

GR_REGISTER_BLOCK(gnuradio4::linux_crypto::KernelKeyringSource)

struct KernelKeyringSource : gr::Block<KernelKeyringSource> {
    using Description = gr::Doc<"Reads key material from the Linux kernel keyring (keyutils). Every 1000 work invocations the key is probed; if it vanishes, buffered material is cleared.See reload_key().">;

    gr::PortOut<std::uint8_t> out{};
    gr::Annotated<detail::KeySerialNative, "key_id", gr::Doc<"_kernel key serial">>            key_id{};
    gr::Annotated<bool, "auto_repeat", gr::Doc<"Repeat key bytes cyclic on the output">> auto_repeat = true;

    GR_MAKE_REFLECTABLE(KernelKeyringSource, out, key_id, auto_repeat);

private:
    std::vector<std::uint8_t> _data{};
    std::size_t               _off{0UZ};
    unsigned                  _hb{0U};

    void clearSecrets() noexcept {
        if (!_data.empty()) {
            OPENSSL_cleanse(_data.data(), _data.size());
        }
        _data.clear();
        _off = 0UZ;
    }

    void loadPayload() {
        if (!detail::keyring_read_payload(key_id.value, _data)) {
            clearSecrets();
            return;
        }
        _off = 0UZ;
    }

public:
    void reload_key() {
        _off = 0UZ;
        loadPayload();
    }

    void start() { loadPayload(); }

    void stop() { clearSecrets(); }

    void settingsChanged(const gr::property_map& /*o*/, const gr::property_map& ne) {
        if (ne.contains("key_id") || ne.contains("auto_repeat")) {
            clearSecrets();
            loadPayload();
        }
    }

    [[nodiscard]] gr::work::Status processBulk(gr::OutputSpanLike auto& outp) noexcept {
        ++_hb;
        if ((_hb % 1000U) == 0U && !_data.empty()) {
            if (!detail::keyring_probe(key_id.value)) {
                clearSecrets();
            }
        }

        const auto nAvail = outp.size();
        if (nAvail == 0UZ) {
            outp.publish(0UZ);
            return gr::work::Status::OK;
        }

        if (_data.empty()) {
            std::memset(outp.data(), 0, nAvail);
            outp.publish(nAvail);
            return gr::work::Status::OK;
        }

        if (auto_repeat.value) {
            for (std::size_t i = 0UZ; i < nAvail; ++i) {
                outp[static_cast<std::ptrdiff_t>(i)] = _data[i % _data.size()];
            }
        } else {
            const std::size_t remain = (_off < _data.size()) ? (_data.size() - _off) : 0UZ;
            const std::size_t take     = std::min(nAvail, remain);
            if (take > 0UZ) {
                std::memcpy(outp.data(), _data.data() + _off, take);
                _off += take;
            }
            if (take < nAvail) {
                std::memset(outp.data() + static_cast<std::ptrdiff_t>(take), 0, nAvail - take);
            }
        }
        outp.publish(nAvail);
        return gr::work::Status::OK;
    }
};

} // namespace gnuradio4::linux_crypto

#endif

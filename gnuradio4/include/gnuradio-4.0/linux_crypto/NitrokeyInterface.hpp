// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_NITROKEYINTERFACE_HPP
#define GNURADIO4_LINUX_CRYPTO_NITROKEYINTERFACE_HPP

#include <gnuradio-4.0/Block.hpp>
#include <gnuradio-4.0/BlockRegistry.hpp>
#include <gnuradio-4.0/annotated.hpp>
#include <gnuradio-4.0/meta/utils.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#ifdef HAVE_NITROKEY
#include <libnitrokey/NitrokeyManager.h>
#endif

namespace gnuradio4::linux_crypto {

GR_REGISTER_BLOCK(gnuradio4::linux_crypto::NitrokeyInterface)

struct NitrokeyInterface : gr::Block<NitrokeyInterface> {
    using Description =
        gr::Doc<"Nitrokey password-safe reads via libnitrokey when built with HAVE_NITROKEY; otherwise outputs zeros with a stderr warning.">;

    gr::PortOut<std::uint8_t> out{};
    gr::Annotated<int, "slot", gr::Doc<"Password safe slot 0-15">>                   slot        = 0;
    gr::Annotated<bool, "auto_repeat", gr::Doc<"Repeat key stream cyclically">> auto_repeat = true;

    GR_MAKE_REFLECTABLE(NitrokeyInterface, out, slot, auto_repeat);

private:
    mutable std::mutex        _mx{};
    std::vector<std::uint8_t> _data{};
    std::size_t               _off{0UZ};
    unsigned                  _hb{0U};
    bool                      _connected{false};
    std::string               _device_info{"Nitrokey (unavailable)"};

#ifdef HAVE_NITROKEY
    nitrokey::NitrokeyManager* _mgr{nullptr};
#endif

    void clearSecrets() noexcept {
        if (!_data.empty()) {
            OPENSSL_cleanse(_data.data(), _data.size());
        }
        _data.clear();
        _off = 0UZ;
    }

    static void warnOnceDegraded() {
        static bool warned = false;
        if (!warned) {
            warned = true;
            std::cerr << "NitrokeyInterface: degraded mode (no libnitrokey or no device); output is zero.\n";
        }
    }

    void tryConnectLocked() {
#ifdef HAVE_NITROKEY
        try {
            _mgr = nitrokey::NitrokeyManager::instance().get();
            if (_mgr != nullptr && _mgr->connect() && _mgr->is_connected()) {
                _connected   = true;
                _device_info = "Nitrokey connected";
                return;
            }
        } catch (...) {
        }
#endif
        _connected = false;
#ifdef HAVE_NITROKEY
        _mgr = nullptr;
#endif
        warnOnceDegraded();
    }

    void loadSecretLocked() {
        clearSecrets();
#ifndef HAVE_NITROKEY
        tryConnectLocked();
        return;
#else
        if (!_mgr || !_connected) {
            tryConnectLocked();
            if (!_connected) {
                return;
            }
        }
        if (slot.value < 0 || slot.value > 15) {
            return;
        }
        try {
            char* pw = _mgr->get_password_safe_slot_password(static_cast<uint8_t>(slot.value));
            if (pw != nullptr && pw[0] != '\0') {
                std::string s(pw);
                _data.assign(s.begin(), s.end());
                _off = 0UZ;
            }
        } catch (...) {
            clearSecrets();
            _connected = false;
        }
#endif
    }

public:
    void reload_key() {
        std::lock_guard<std::mutex> lk{_mx};
        _off = 0UZ;
        tryConnectLocked();
        loadSecretLocked();
    }

    void start() { reload_key(); }

    void stop() {
        std::lock_guard<std::mutex> lk{_mx};
#ifdef HAVE_NITROKEY
        _mgr = nullptr;
#endif
        _connected = false;
        clearSecrets();
    }

    [[nodiscard]] std::vector<int> get_available_slots() const {
        std::lock_guard<std::mutex> lk{_mx};
        std::vector<int> slots;
#ifdef HAVE_NITROKEY
        if (_mgr == nullptr || !_connected) {
            return slots;
        }
        try {
            auto st = _mgr->get_password_safe_slot_status();
            for (std::size_t i = 0UZ; i < st.size() && i < 16UZ; ++i) {
                if (st[i] != 0) {
                    slots.push_back(static_cast<int>(i));
                }
            }
        } catch (...) {
        }
#else
        (void)this;
#endif
        return slots;
    }

    [[nodiscard]] std::string get_device_info() const {
        std::lock_guard<std::mutex> lk{_mx};
        return _device_info;
    }

    void settingsChanged(const gr::property_map& /*o*/, const gr::property_map& ne) {
        if (ne.contains("slot") || ne.contains("auto_repeat")) {
            reload_key();
        }
    }

    [[nodiscard]] gr::work::Status processBulk(gr::OutputSpanLike auto& outp) noexcept {
        ++_hb;
        const auto nAvail = outp.size();

        {
            std::lock_guard<std::mutex> lk{_mx};
            if ((_hb % 1000U) == 0U) {
                tryConnectLocked();
                loadSecretLocked();
            }

            if (nAvail == 0UZ) {
                outp.publish(0UZ);
                return gr::work::Status::OK;
            }

            if (_data.empty() || !_connected) {
                // fall through to zeros below
            } else if (auto_repeat.value) {
                for (std::size_t i = 0UZ; i < nAvail; ++i) {
                    outp[static_cast<std::ptrdiff_t>(i)] = _data[i % _data.size()];
                }
                outp.publish(nAvail);
                return gr::work::Status::OK;
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
                outp.publish(nAvail);
                return gr::work::Status::OK;
            }
        }

        if (nAvail == 0UZ) {
            outp.publish(0UZ);
            return gr::work::Status::OK;
        }
        std::memset(outp.data(), 0, nAvail);
        outp.publish(nAvail);
        return gr::work::Status::OK;
    }
};

} // namespace gnuradio4::linux_crypto

#endif

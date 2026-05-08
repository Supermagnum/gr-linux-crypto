// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_BRAINPOOLECIESMULTIENCRYPT_HPP
#define GNURADIO4_LINUX_CRYPTO_BRAINPOOLECIESMULTIENCRYPT_HPP

#include <gnuradio-4.0/Block.hpp>
#include <gnuradio-4.0/BlockRegistry.hpp>
#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/Value.hpp>
#include <gnuradio-4.0/annotated.hpp>

#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>
#include <gnuradio-4.0/linux_crypto/detail/CallsignKeyStore.hpp>
#include <gnuradio-4.0/linux_crypto/detail/Helpers.hpp>
#include <gnuradio-4.0/linux_crypto/detail/MultiRecipientEcies.hpp>
#include <gnuradio-4.0/linux_crypto/detail/MsgPost.hpp>

#include <cstdlib>

#include <algorithm>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace gnuradio4::linux_crypto {

GR_REGISTER_BLOCK(gnuradio4::linux_crypto::BrainpoolEciesMultiEncrypt)

struct BrainpoolEciesMultiEncrypt : gr::Block<BrainpoolEciesMultiEncrypt, gr::NoTagPropagation> {
    using Description = gr::Doc<"Multi-recipient ECIES format v1 (AES-GCM payload) with callsign-keyed PEM store (JSON groups supported). Max 25 recipients.">;

    gr::MsgPortIn               msg_pdu_in{};
    gr::MsgPortOut              msg_pdu_out{};

    gr::Annotated<std::vector<std::string>, "callsign_tokens",
        gr::Doc<"Callsigns or group names from JSON store; expanded and unique-capped at 25">>
                                                                   callsign_tokens{};
    gr::Annotated<std::string, "key_store_path", gr::Doc<"Path to callsign_keys.json (empty uses $HOME/.gnuradio/)">> key_store_path{};
    gr::Annotated<std::string, "curve", gr::Doc<"brainpool curve">>               curve_name{std::string("brainpoolP256r1")};
    gr::Annotated<std::string, "kdf_info", gr::Doc<"HKDF info for per-recipient ECIES wrap">> kdf_info{std::string("gr-linux-crypto-ecies-v1")};

    GR_MAKE_REFLECTABLE(BrainpoolEciesMultiEncrypt, msg_pdu_in, msg_pdu_out, callsign_tokens, key_store_path, curve_name, kdf_info);

private:
    detail::CallsignKeyStore _store{};
    BrainpoolEcImpl::Curve   _curve{BrainpoolEcImpl::Curve::BRAINPOOLP256R1};

    static std::string defaultStorePath() {
        if (const char* h = std::getenv("HOME"); h != nullptr) {
            return std::string(h) + "/.gnuradio/callsign_keys.json";
        }
        return std::string{".gnuradio/callsign_keys.json"};
    }

    bool reloadStorePath() {
        std::string p = key_store_path.value.empty() ? defaultStorePath() : key_store_path.value;
        return _store.loadFile(p);
    }

    void rebuildCurve() { _curve = BrainpoolEcImpl::string_to_curve(curve_name.value); }

public:
    void start() {
        reloadStorePath();
        rebuildCurve();
    }

    void settingsChanged(const gr::property_map&, const gr::property_map& ne) {
        if (ne.contains("key_store_path")) {
            reloadStorePath();
        }
        if (ne.contains("curve")) {
            rebuildCurve();
        }
    }

    [[nodiscard]] gr::work::Status processBulk() noexcept { return gr::work::Status::OK; }

    void processMessages(gr::MsgPortIn& port, std::span<const gr::Message> msgs) {
        if (std::addressof(port) != std::addressof(msg_pdu_in)) {
            return;
        }
        for (const gr::Message& m : msgs) {
            if (!m.data.has_value()) {
                continue;
            }
            const gr::property_map& body = *m.data;
            const auto*               tb   = detail::tensorBytesFromMap(body, std::string_view("pdu_data"));
            if (tb == nullptr) {
                throw std::runtime_error("BrainpoolEciesMultiEncrypt: pdu_data missing");
            }
            if (callsign_tokens.value.empty()) {
                throw std::runtime_error("BrainpoolEciesMultiEncrypt: callsign_tokens empty");
            }

            auto expanded = _store.expandRecipients(callsign_tokens.value);
            if (expanded.empty()) {
                throw std::runtime_error("BrainpoolEciesMultiEncrypt: no recipients after group expansion");
            }
            std::set<std::string>              seen{};
            std::vector<std::string>           rec;
            rec.reserve(expanded.size());
            for (const std::string& c : expanded) {
                if (seen.insert(c).second) {
                    rec.push_back(c);
                }
            }
            if (rec.size() > 25UZ) {
                throw std::runtime_error("BrainpoolEciesMultiEncrypt: more than 25 unique recipients");
            }

            std::vector<std::uint8_t> wire;
            const bool ok = detail::multiRecipientEncrypt(_curve, _store,
                std::span<const std::string>(rec.data(), rec.size()), std::string_view(kdf_info.value.data(), kdf_info.value.size()),
                std::span<const std::uint8_t>(tb->data(), tb->size()), wire);

            if (!ok) {
                throw std::runtime_error("BrainpoolEciesMultiEncrypt: encrypt failed");
            }

            gr::property_map out(body.get_allocator());
            for (const auto& kv : body) {
                out.emplace(kv.first, kv.second);
            }
            out.insert_or_assign(
                gr::convert_string_domain(std::string_view("pdu_data")), gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(wire))));
            detail::postPropertyNotify(msg_pdu_out, std::move(out));
        }
    }
};

} // namespace gnuradio4::linux_crypto

#endif

// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_BRAINPOOLECIESDECRYPT_HPP
#define GNURADIO4_LINUX_CRYPTO_BRAINPOOLECIESDECRYPT_HPP

#include <gnuradio-4.0/Block.hpp>
#include <gnuradio-4.0/BlockRegistry.hpp>
#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/Value.hpp>
#include <gnuradio-4.0/annotated.hpp>

#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>
#include <gnuradio-4.0/linux_crypto/detail/EciesCodec.hpp>
#include <gnuradio-4.0/linux_crypto/detail/Helpers.hpp>
#include <gnuradio-4.0/linux_crypto/detail/MsgPost.hpp>

#include <openssl/evp.h>

#include <stdexcept>
#include <string>

namespace gnuradio4::linux_crypto {

GR_REGISTER_BLOCK(gnuradio4::linux_crypto::BrainpoolEciesDecrypt)

struct BrainpoolEciesDecrypt : gr::Block<BrainpoolEciesDecrypt, gr::NoTagPropagation> {
    using Description = gr::Doc<"Single-recipient Brainpool ECIES decrypt (PEM private key). Expects ciphertext wire in pdu_data.">;

    gr::MsgPortIn               msg_pdu_in{};
    gr::MsgPortOut              msg_pdu_out{};

    gr::Annotated<std::string, "curve", gr::Doc<"brainpool curve name">> curve_name{std::string("brainpoolP256r1")};
    gr::Annotated<std::string, "private_key_pem", gr::Doc<"PEM private key">>                       private_key_pem{};
    gr::Annotated<std::string, "kdf_info", gr::Doc<"HKDF info (must match encrypt)">>                kdf_info{std::string("gr-linux-crypto-ecies-v1")};

    GR_MAKE_REFLECTABLE(BrainpoolEciesDecrypt, msg_pdu_in, msg_pdu_out, curve_name, private_key_pem, kdf_info);

private:
    BrainpoolEcImpl _ec{BrainpoolEcImpl::Curve::BRAINPOOLP256R1};
    EVP_PKEY*       _priv{nullptr};

    void rebuildCurve() { _ec.set_curve(BrainpoolEcImpl::string_to_curve(curve_name.value)); }

    void loadPriv() {
        if (_priv != nullptr) {
            EVP_PKEY_free(_priv);
            _priv = nullptr;
        }
        const std::string& pem = private_key_pem.value;
        if (pem.empty()) {
            return;
        }
        _priv = detail::loadPrivateKeyFromPemString(std::string_view(pem.data(), pem.size()));
    }

public:
    void start() {
        rebuildCurve();
        loadPriv();
    }

    void stop() {
        if (_priv != nullptr) {
            EVP_PKEY_free(_priv);
            _priv = nullptr;
        }
    }

    void settingsChanged(const gr::property_map&, const gr::property_map& ne) {
        if (ne.contains("curve")) {
            rebuildCurve();
        }
        if (ne.contains("private_key_pem")) {
            loadPriv();
        }
    }

    [[nodiscard]] gr::work::Status processBulk() noexcept { return gr::work::Status::OK; }

    void processMessages(gr::MsgPortIn& port, std::span<const gr::Message> msgs) {
        if (std::addressof(port) != std::addressof(msg_pdu_in)) {
            return;
        }
        for (const gr::Message& m : msgs) {
            if (!_priv || !m.data.has_value()) {
                continue;
            }
            const gr::property_map& body = *m.data;
            const auto*               tb   = detail::tensorBytesFromMap(body, std::string_view("pdu_data"));
            if (tb == nullptr) {
                throw std::runtime_error("BrainpoolEciesDecrypt: pdu_data missing");
            }
            std::vector<std::uint8_t> plain;
            if (!detail::eciesDecryptPem(_priv, std::string_view(kdf_info.value.data(), kdf_info.value.size()),
                    std::span<const std::uint8_t>(tb->data(), tb->size()), plain)) {
                throw std::runtime_error("BrainpoolEciesDecrypt: decryption failed");
            }
            gr::property_map out(body.get_allocator());
            for (const auto& kv : body) {
                out.emplace(kv.first, kv.second);
            }
            out.insert_or_assign(
                gr::convert_string_domain(std::string_view("pdu_data")), gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(plain))));
            detail::postPropertyNotify(msg_pdu_out, std::move(out));
        }
    }
};

} // namespace gnuradio4::linux_crypto

#endif

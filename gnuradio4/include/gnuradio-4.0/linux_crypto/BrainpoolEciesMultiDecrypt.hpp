// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_BRAINPOOLECIESMULTIDECRYPT_HPP
#define GNURADIO4_LINUX_CRYPTO_BRAINPOOLECIESMULTIDECRYPT_HPP

#include <gnuradio-4.0/Block.hpp>
#include <gnuradio-4.0/BlockRegistry.hpp>
#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/Value.hpp>
#include <gnuradio-4.0/annotated.hpp>

#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>
#include <gnuradio-4.0/linux_crypto/detail/Helpers.hpp>
#include <gnuradio-4.0/linux_crypto/detail/MultiRecipientEcies.hpp>
#include <gnuradio-4.0/linux_crypto/detail/MsgPost.hpp>

#include <cctype>
#include <stdexcept>
#include <string>

namespace gnuradio4::linux_crypto {

GR_REGISTER_BLOCK(gnuradio4::linux_crypto::BrainpoolEciesMultiDecrypt)

struct BrainpoolEciesMultiDecrypt : gr::Block<BrainpoolEciesMultiDecrypt, gr::NoTagPropagation> {
    using Description = gr::Doc<"Decrypt multi-recipient v1 payloads for matching callsign (tries keyed block embedded in wire).">;

    gr::MsgPortIn               msg_pdu_in{};
    gr::MsgPortOut              msg_pdu_out{};

    gr::Annotated<std::string, "recipient_callsign", gr::Doc<"This station callsign (upper-case recommended)">> recipient_callsign{};
    gr::Annotated<std::string, "private_key_pem", gr::Doc<"PEM Brainpool EC private">> private_key_pem{};
    gr::Annotated<std::string, "curve", gr::Doc<"Must match ciphertext">>                            curve_name{std::string("brainpoolP256r1")};
    gr::Annotated<std::string, "kdf_info", gr::Doc<"HKDF info used at encrypt">> kdf_info{std::string("gr-linux-crypto-ecies-v1")};

    GR_MAKE_REFLECTABLE(BrainpoolEciesMultiDecrypt, msg_pdu_in, msg_pdu_out, recipient_callsign, private_key_pem, curve_name, kdf_info);

private:
    BrainpoolEcImpl::Curve _curve{BrainpoolEcImpl::Curve::BRAINPOOLP256R1};
    void                   rebuildCurve() { _curve = BrainpoolEcImpl::string_to_curve(curve_name.value); }

    static std::string upperTrim(std::string s) {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
            s.pop_back();
        }
        for (char& ch : s) {
            ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        }
        return s;
    }

public:
    void start() { rebuildCurve(); }

    void settingsChanged(const gr::property_map&, const gr::property_map& ne) {
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
            const auto*               tb = detail::tensorBytesFromMap(body, std::string_view("pdu_data"));
            if (tb == nullptr) {
                throw std::runtime_error("BrainpoolEciesMultiDecrypt: pdu_data missing");
            }
            std::vector<std::uint8_t> plain;
            const std::string         cs       = upperTrim(recipient_callsign.value);
            const std::string_view    kdfView{kdf_info.value};
            const std::string_view    pkView{private_key_pem.value};
            if (!detail::multiRecipientDecrypt(_curve, std::string_view{cs.data(), cs.size()}, pkView, kdfView,
                    std::span<const std::uint8_t>(tb->data(), tb->size()), plain)) {
                throw std::runtime_error("BrainpoolEciesMultiDecrypt: decrypt failed");
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

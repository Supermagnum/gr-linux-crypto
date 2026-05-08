// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_BRAINPOOLECDSAVERIFY_HPP
#define GNURADIO4_LINUX_CRYPTO_BRAINPOOLECDSAVERIFY_HPP

#include <gnuradio-4.0/Block.hpp>
#include <gnuradio-4.0/BlockRegistry.hpp>
#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/Value.hpp>
#include <gnuradio-4.0/annotated.hpp>

#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>
#include <gnuradio-4.0/linux_crypto/detail/BrainpoolHash.hpp>
#include <gnuradio-4.0/linux_crypto/detail/Helpers.hpp>
#include <gnuradio-4.0/linux_crypto/detail/MsgPost.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <stdexcept>
#include <string>

namespace gnuradio4::linux_crypto {

GR_REGISTER_BLOCK(gnuradio4::linux_crypto::BrainpoolEcdsaVerify)

struct BrainpoolEcdsaVerify : gr::Block<BrainpoolEcdsaVerify, gr::NoTagPropagation> {
    using Description =
        gr::Doc<"Brainpool ECDSA verification using pdu_data (message bytes) and pdu_signature (DER). Sets auth_ok in the outbound property map.">;

    gr::MsgPortIn  msg_pdu_in{};
    gr::MsgPortOut msg_pdu_out{};

    gr::Annotated<std::string, "curve", gr::Doc<"brainpool curve name">>       curve_name{std::string("brainpoolP256r1")};
    gr::Annotated<std::string, "hash_algorithm", gr::Doc<"sha256|sha384|sha512">> hash_algorithm{std::string("sha256")};
    gr::Annotated<std::string, "public_key_pem", gr::Doc<"Recipient public key">>  public_key_pem{};

    GR_MAKE_REFLECTABLE(BrainpoolEcdsaVerify, msg_pdu_in, msg_pdu_out, curve_name, hash_algorithm, public_key_pem);

private:
    BrainpoolEcImpl _ec{BrainpoolEcImpl::Curve::BRAINPOOLP256R1};
    EVP_PKEY*       _pub{nullptr};

    void rebuildCurve() { _ec.set_curve(BrainpoolEcImpl::string_to_curve(curve_name.value)); }

    void loadPublic() {
        if (_pub != nullptr) {
            EVP_PKEY_free(_pub);
            _pub = nullptr;
        }
        const std::string& pem = public_key_pem.value;
        if (pem.empty()) {
            return;
        }
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (bio == nullptr) {
            return;
        }
        _pub = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
    }

public:
    void start() {
        rebuildCurve();
        loadPublic();
    }

    void stop() {
        if (_pub != nullptr) {
            EVP_PKEY_free(_pub);
            _pub = nullptr;
        }
    }

    void settingsChanged(const gr::property_map&, const gr::property_map& ne) {
        if (ne.contains("curve")) {
            rebuildCurve();
        }
        if (ne.contains("public_key_pem")) {
            loadPublic();
        }
    }

    [[nodiscard]] gr::work::Status processBulk() noexcept { return gr::work::Status::OK; }

    void processMessages(gr::MsgPortIn& port, std::span<const gr::Message> msgs) {
        if (std::addressof(port) != std::addressof(msg_pdu_in)) {
            return;
        }
        for (const gr::Message& m : msgs) {
            if (!_pub || !m.data.has_value()) {
                continue;
            }
            const gr::property_map& body = *m.data;
            const auto*               msg  = detail::tensorBytesFromMap(body, std::string_view("pdu_data"));
            const auto*               sig  = detail::tensorBytesFromMap(body, std::string_view("pdu_signature"));
            if (msg == nullptr || sig == nullptr) {
                throw std::runtime_error("BrainpoolEcdsaVerify: pdu_data/pdu_signature required");
            }
            const bool ok = _ec.verify(msg->data(), msg->size(), sig->data(), sig->size(), _pub, detail::hashFromName(hash_algorithm.value));
            gr::property_map out(body.get_allocator());
            for (const auto& kv : body) {
                out.emplace(kv.first, kv.second);
            }
            out.insert_or_assign(gr::convert_string_domain(std::string_view("auth_ok")), gr::pmt::Value(ok));
            detail::postPropertyNotify(msg_pdu_out, std::move(out));
        }
    }
};

} // namespace gnuradio4::linux_crypto

#endif

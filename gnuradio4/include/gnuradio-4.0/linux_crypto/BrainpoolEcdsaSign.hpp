// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_BRAINPOOLECDSASIGN_HPP
#define GNURADIO4_LINUX_CRYPTO_BRAINPOOLECDSASIGN_HPP

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

GR_REGISTER_BLOCK(gnuradio4::linux_crypto::BrainpoolEcdsaSign)

struct BrainpoolEcdsaSign : gr::Block<BrainpoolEcdsaSign, gr::NoTagPropagation> {
    using Description = gr::Doc<"Brainpool ECDSA signatures (DER) using OpenSSL EVP. Input/output on message ports pdu_data.">;

    gr::MsgPortIn               msg_pdu_in{};
    gr::MsgPortOut              msg_pdu_out{};

    gr::Annotated<std::string, "curve", gr::Doc<"brainpoolP256r1|brainpoolP384r1|brainpoolP512r1">> curve_name{
        std::string("brainpoolP256r1")};
    gr::Annotated<std::string, "hash_algorithm", gr::Doc<"sha256|sha384|sha512">>               hash_algorithm{std::string("sha256")};
    gr::Annotated<std::string, "private_key_pem", gr::Doc<"PEM private key">>                    private_key_pem{};

    GR_MAKE_REFLECTABLE(BrainpoolEcdsaSign, msg_pdu_in, msg_pdu_out, curve_name, hash_algorithm, private_key_pem);

private:
    BrainpoolEcImpl _ec{BrainpoolEcImpl::Curve::BRAINPOOLP256R1};
    EVP_PKEY*       _pk{nullptr};

    void rebuildCurve() {
        _ec.set_curve(BrainpoolEcImpl::string_to_curve(curve_name.value));
    }

    void loadPrivate() {
        if (_pk != nullptr) {
            EVP_PKEY_free(_pk);
            _pk = nullptr;
        }
        const std::string& pem = private_key_pem.value;
        if (pem.empty()) {
            return;
        }
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (bio == nullptr) {
            return;
        }
        _pk = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
    }

public:
    void start() {
        rebuildCurve();
        loadPrivate();
    }

    void stop() {
        if (_pk != nullptr) {
            EVP_PKEY_free(_pk);
            _pk = nullptr;
        }
    }

    void settingsChanged(const gr::property_map& /*old*/, const gr::property_map& ne) {
        if (ne.contains("curve")) {
            rebuildCurve();
        }
        if (ne.contains("private_key_pem")) {
            loadPrivate();
        }
    }

    [[nodiscard]] gr::work::Status processBulk() noexcept { return gr::work::Status::OK; }

    void processMessages(gr::MsgPortIn& port, std::span<const gr::Message> msgs) {
        if (std::addressof(port) != std::addressof(msg_pdu_in)) {
            return;
        }
        for (const gr::Message& m : msgs) {
            if (!_pk || !m.data.has_value()) {
                continue;
            }
            const gr::property_map& body = *m.data;
            const auto*               tb  = detail::tensorBytesFromMap(body, std::string_view("pdu_data"));
            if (tb == nullptr || tb->empty()) {
                throw std::runtime_error("BrainpoolEcdsaSign: pdu_data missing");
            }
            std::vector<std::uint8_t> sig = _ec.sign(tb->data(), tb->size(), _pk, detail::hashFromName(hash_algorithm.value));
            gr::property_map          out(body.get_allocator());
            for (const auto& [k, v] : body) {
                out.emplace(k, v);
            }
            out.insert_or_assign(
                gr::convert_string_domain(std::string_view("pdu_data")), gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(sig))));
            detail::postPropertyNotify(msg_pdu_out, std::move(out));
        }
    }
};

} // namespace gnuradio4::linux_crypto

#endif

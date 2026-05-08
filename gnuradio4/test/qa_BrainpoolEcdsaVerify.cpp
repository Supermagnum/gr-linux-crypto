// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Sequence.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/linux_crypto/BrainpoolEcdsaVerify.hpp>
#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>
#include <gnuradio-4.0/linux_crypto/detail/BrainpoolHash.hpp>

#include <openssl/evp.h>
#include <string>
#include <string_view>
#include <vector>

using namespace boost::ut;

namespace {

void pushVerify(gr::MsgPortOut& downstream, std::vector<std::uint8_t> msg, std::vector<std::uint8_t> sig) {
    gr::property_map pm;
    pm[gr::convert_string_domain(std::string_view("pdu_data"))] = gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(msg)));
    pm[gr::convert_string_domain(std::string_view("pdu_signature"))] = gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(sig)));
    gr::Message m;
    m.cmd  = gr::message::Command::Notify;
    m.data = std::move(pm);
    auto w = downstream.streamWriter().template reserve<gr::SpanReleasePolicy::ProcessAll>(1UZ);
    w[0]   = std::move(m);
    w.publish(1UZ);
}

bool readAuthOk(const gr::Message& reply) {
    if (!reply.data.has_value()) {
        return false;
    }
    const gr::property_map& pmap = *reply.data;
    const std::pmr::string key   = gr::convert_string_domain(std::string_view("auth_ok"));
    const auto               it    = pmap.find(key);
    if (it == pmap.end()) {
        return false;
    }
    if (const auto* b = it->second.get_if<bool>()) {
        return *b;
    }
    return false;
}

const boost::ut::suite<"BrainpoolEcdsaVerify"> suite = [] {
    "verify accepts good signature"_test = [] {
        using Impl = gnuradio4::linux_crypto::BrainpoolEcImpl;
        using C    = Impl::Curve;
        Impl                          ec(C::BRAINPOOLP256R1);
        const Impl::KeyPair           kp = ec.generate_keypair();
        std::vector<std::uint8_t> pub_b  = Impl::serialize_public_key(kp.public_key);
        std::string               pub(reinterpret_cast<const char*>(pub_b.data()), pub_b.size());
        std::vector<std::uint8_t> msg{'h', 'i'};
        std::vector<std::uint8_t> sig = ec.sign(msg.data(), msg.size(), kp.private_key,
            gnuradio4::linux_crypto::detail::hashFromName(std::string_view("sha256")));

        gnuradio4::linux_crypto::BrainpoolEcdsaVerify blk;
        blk.curve_name.value      = Impl::curve_to_string(C::BRAINPOOLP256R1);
        blk.hash_algorithm.value  = std::string("sha256");
        blk.public_key_pem.value   = pub;
        blk.init(std::make_shared<gr::Sequence>());
        blk.start();

        gr::MsgPortOut src;
        gr::MsgPortIn  snk;
        expect(src.connect(blk.msg_pdu_in).has_value());
        expect(blk.msg_pdu_out.connect(snk).has_value());
        pushVerify(src, msg, sig);
        blk.processScheduledMessages();
        auto reader = snk.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        expect(readAuthOk(reader[0]));
        EVP_PKEY_free(kp.private_key);
        EVP_PKEY_free(kp.public_key);
        expect(reader.consume(reader.size()));
    };

    "verify rejects tampered message"_test = [] {
        using Impl = gnuradio4::linux_crypto::BrainpoolEcImpl;
        using C    = Impl::Curve;
        Impl                          ec(C::BRAINPOOLP256R1);
        const Impl::KeyPair           kp = ec.generate_keypair();
        std::vector<std::uint8_t> pub_b  = Impl::serialize_public_key(kp.public_key);
        std::string               pub(reinterpret_cast<const char*>(pub_b.data()), pub_b.size());
        std::vector<std::uint8_t> msg{'x'};
        std::vector<std::uint8_t> sig = ec.sign(msg.data(), msg.size(), kp.private_key,
            gnuradio4::linux_crypto::detail::hashFromName(std::string_view("sha256")));
        msg[0] = 'y';

        gnuradio4::linux_crypto::BrainpoolEcdsaVerify blk;
        blk.curve_name.value     = Impl::curve_to_string(C::BRAINPOOLP256R1);
        blk.hash_algorithm.value = std::string("sha256");
        blk.public_key_pem.value = pub;
        blk.init(std::make_shared<gr::Sequence>());
        blk.start();
        gr::MsgPortOut src;
        gr::MsgPortIn  snk;
        expect(src.connect(blk.msg_pdu_in).has_value());
        expect(blk.msg_pdu_out.connect(snk).has_value());
        pushVerify(src, msg, sig);
        blk.processScheduledMessages();
        auto reader = snk.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        expect(!readAuthOk(reader[0]));
        EVP_PKEY_free(kp.private_key);
        EVP_PKEY_free(kp.public_key);
        expect(reader.consume(reader.size()));
    };
};

} // namespace

int main() { return boost::ut::cfg<boost::ut::override>.run(); }

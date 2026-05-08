// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Sequence.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/linux_crypto/BrainpoolEcdsaSign.hpp>
#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>

#include <openssl/evp.h>

#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace boost::ut;

namespace {

void pushPdu(gr::MsgPortOut& downstream, std::vector<std::uint8_t> pdu) {
    gr::property_map pm;
    pm[gr::convert_string_domain(std::string_view("pdu_data"))] = gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(pdu)));
    gr::Message m;
    m.cmd  = gr::message::Command::Notify;
    m.data = std::move(pm);
    auto w = downstream.streamWriter().template reserve<gr::SpanReleasePolicy::ProcessAll>(1UZ);
    w[0]   = std::move(m);
    w.publish(1UZ);
}

std::vector<std::uint8_t> getPduBytes(const gr::Message& reply) {
    if (!reply.data.has_value()) {
        throw std::runtime_error("missing data");
    }
    const gr::property_map& pmap = *reply.data;
    const auto it = pmap.find(gr::convert_string_domain(std::string_view("pdu_data")));
    if (it == pmap.end()) {
        throw std::runtime_error("missing pdu_data");
    }
    const auto* t = it->second.get_if<gr::Tensor<std::uint8_t>>();
    if (t == nullptr) {
        throw std::runtime_error("bad tensor");
    }
    return std::vector<std::uint8_t>(t->begin(), t->end());
}

const boost::ut::suite<"BrainpoolEcdsaSign"> signSuite = [] {
    using C = gnuradio4::linux_crypto::BrainpoolEcImpl::Curve;

    "sign emits non-empty DER signature"_test = [] {
        gnuradio4::linux_crypto::BrainpoolEcImpl ec(C::BRAINPOOLP256R1);
        const auto kp = ec.generate_keypair();
        expect(kp.private_key != nullptr);
        expect(kp.public_key != nullptr);

        std::vector<std::uint8_t> priv_blob = ec.serialize_private_key(kp.private_key, "");
        std::string               priv_pem(reinterpret_cast<const char*>(priv_blob.data()), priv_blob.size());

        gnuradio4::linux_crypto::BrainpoolEcdsaSign blk;
        blk.curve_name.value =
            gnuradio4::linux_crypto::BrainpoolEcImpl::curve_to_string(gnuradio4::linux_crypto::BrainpoolEcImpl::Curve::BRAINPOOLP256R1);
        blk.hash_algorithm.value    = std::string("sha256");
        blk.private_key_pem.value   = priv_pem;
        blk.init(std::make_shared<gr::Sequence>());
        blk.start();

        gr::MsgPortOut upstream;
        gr::MsgPortIn  sink;
        expect(upstream.connect(blk.msg_pdu_in).has_value());
        expect(blk.msg_pdu_out.connect(sink).has_value());

        std::vector<std::uint8_t> msg{'t', 'e', 's', 't'};
        pushPdu(upstream, msg);
        blk.processScheduledMessages();

        auto reader = sink.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        const auto& reply = reader[0];
        expect(reply.data.has_value());
        const auto sig = getPduBytes(reply);
        expect(sig.size() > 8UZ);
        EVP_PKEY_free(kp.private_key);
        EVP_PKEY_free(kp.public_key);
        expect(reader.consume(reader.size()));
    };
};

} // namespace

int main() { return boost::ut::cfg<boost::ut::override>.run(); }

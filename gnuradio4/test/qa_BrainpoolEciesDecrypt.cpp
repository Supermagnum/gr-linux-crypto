// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Sequence.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/linux_crypto/BrainpoolEciesDecrypt.hpp>
#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>
#include <gnuradio-4.0/linux_crypto/detail/EciesCodec.hpp>
#include <gnuradio-4.0/linux_crypto/detail/Helpers.hpp>

#include <openssl/evp.h>

#include <algorithm>
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

const boost::ut::suite<"BrainpoolEciesDecrypt"> suite = [] {
    "Decrypt block matches detail encrypt"_test = [] {
        using Impl = gnuradio4::linux_crypto::BrainpoolEcImpl;
        using C    = Impl::Curve;
        Impl ec(C::BRAINPOOLP256R1);
        const auto kp                       = ec.generate_keypair();
        std::vector<std::uint8_t> plainOrig = {'a', 'b', 'c'};

        std::vector<std::uint8_t> wire;
        expect(gnuradio4::linux_crypto::detail::eciesEncryptPem(ec, kp.public_key,
            std::string_view("gr-linux-crypto-ecies-v1"), std::span<const std::uint8_t>(plainOrig.data(), plainOrig.size()), wire));

        std::vector<std::uint8_t> priv_blob = ec.serialize_private_key(kp.private_key, "");
        std::string               priv(reinterpret_cast<const char*>(priv_blob.data()), priv_blob.size());

        gnuradio4::linux_crypto::BrainpoolEciesDecrypt dec;
        dec.curve_name.value           = Impl::curve_to_string(C::BRAINPOOLP256R1);
        dec.private_key_pem.value      = priv;
        dec.kdf_info.value             = std::string("gr-linux-crypto-ecies-v1");
        dec.init(std::make_shared<gr::Sequence>());
        dec.start();

        gr::MsgPortOut src;
        gr::MsgPortIn  snk;
        expect(src.connect(dec.msg_pdu_in).has_value());
        expect(dec.msg_pdu_out.connect(snk).has_value());
        pushPdu(src, wire);
        dec.processScheduledMessages();

        auto reader = snk.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        expect(reader[0].data.has_value());
        const auto* tb =
            gnuradio4::linux_crypto::detail::tensorBytesFromMap(*reader[0].data, std::string_view("pdu_data"));
        expect(tb != nullptr);
        std::vector<std::uint8_t> got(tb->begin(), tb->end());
        EVP_PKEY_free(kp.private_key);
        EVP_PKEY_free(kp.public_key);
        expect(std::ranges::equal(got, plainOrig));
        expect(reader.consume(reader.size()));
    };
};

} // namespace

int main() { return boost::ut::cfg<boost::ut::override>.run(); }

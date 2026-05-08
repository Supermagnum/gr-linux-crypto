// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Sequence.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/linux_crypto/BrainpoolEciesMultiDecrypt.hpp>
#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>
#include <gnuradio-4.0/linux_crypto/detail/CallsignKeyStore.hpp>
#include <gnuradio-4.0/linux_crypto/detail/Helpers.hpp>
#include <gnuradio-4.0/linux_crypto/detail/MultiRecipientEcies.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

using namespace boost::ut;

namespace {

std::string jsonEscapePem(std::string_view pem) {
    std::string o;
    o.push_back('"');
    for (char ch : pem) {
        switch (ch) {
        case '"':
            o += "\\\"";
            break;
        case '\\':
            o += "\\\\";
            break;
        case '\n':
            o += "\\n";
            break;
        case '\r':
            o += "\\r";
            break;
        default:
            o.push_back(ch);
            break;
        }
    }
    o.push_back('"');
    return o;
}

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

const boost::ut::suite<"BrainpoolEciesMultiDecrypt"> suite = [] {
    "Block decrypt AAA after detail encrypt"_test = [] {
        using Impl  = gnuradio4::linux_crypto::BrainpoolEcImpl;
        using C     = Impl::Curve;

        const auto tmp = std::filesystem::temp_directory_path() / "gr_linux_crypto4_multi_dec.json";
        std::vector<std::string> pubs(3);
        std::vector<std::string> privs(3);
        std::vector<EVP_PKEY*>   keysToFree;

        gnuradio4::linux_crypto::detail::CallsignKeyStore store;
        for (int slot = 0; slot < 3; ++slot) {
            Impl ec(C::BRAINPOOLP256R1);
            auto kp = ec.generate_keypair();
            keysToFree.push_back(kp.private_key);
            keysToFree.push_back(kp.public_key);
            auto pub_blob = Impl::serialize_public_key(kp.public_key);
            auto pr_blob  = ec.serialize_private_key(kp.private_key, "");
            pubs[static_cast<std::size_t>(slot)] = std::string(
                reinterpret_cast<const char*>(pub_blob.data()), reinterpret_cast<const char*>(pub_blob.data()) + pub_blob.size());
            privs[static_cast<std::size_t>(slot)] = std::string(
                reinterpret_cast<const char*>(pr_blob.data()), reinterpret_cast<const char*>(pr_blob.data()) + pr_blob.size());
        }

        {
            const std::string json = std::string("{\"AAA\":") + jsonEscapePem(pubs[0]) + ",\"BBB\":" + jsonEscapePem(pubs[1]) +
                                     ",\"CCC\":" + jsonEscapePem(pubs[2]) + "}";
            std::ofstream f(tmp);
            f << json;
        }
        expect(store.loadFile(tmp.string()));

        std::vector<std::string> recv = {"AAA", "BBB", "CCC"};
        std::vector<std::uint8_t> plain{'d', 'e', 'c'};
        std::vector<std::uint8_t> wire;

        expect(gnuradio4::linux_crypto::detail::multiRecipientEncrypt(C::BRAINPOOLP256R1, store, std::span<std::string>(recv.data(), recv.size()),
            std::string_view("gr-linux-crypto-ecies-v1"), std::span<const std::uint8_t>(plain.data(), plain.size()), wire));

        gnuradio4::linux_crypto::BrainpoolEciesMultiDecrypt dec;
        dec.recipient_callsign.value  = std::string("AAA");
        dec.private_key_pem.value     = privs[0];
        dec.curve_name.value          = Impl::curve_to_string(C::BRAINPOOLP256R1);
        dec.kdf_info.value            = std::string("gr-linux-crypto-ecies-v1");
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
        expect(std::ranges::equal(got, plain));

        for (EVP_PKEY* p : keysToFree) {
            EVP_PKEY_free(p);
        }
        expect(reader.consume(reader.size()));
        std::error_code ec2;
        std::filesystem::remove(tmp, ec2);
    };
};

} // namespace

int main() { return boost::ut::cfg<boost::ut::override>.run(); }

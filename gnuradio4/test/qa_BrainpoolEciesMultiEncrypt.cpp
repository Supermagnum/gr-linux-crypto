// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Sequence.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/linux_crypto/BrainpoolEciesMultiEncrypt.hpp>
#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>
#include <gnuradio-4.0/linux_crypto/detail/Helpers.hpp>
#include <gnuradio-4.0/linux_crypto/detail/MultiRecipientEcies.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <fstream>
#include <filesystem>
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

const boost::ut::suite<"BrainpoolEciesMultiEncrypt"> suite = [] {
    "Three recipients from JSON store each decrypt"_test = [] {
        using Impl = gnuradio4::linux_crypto::BrainpoolEcImpl;
        using C    = Impl::Curve;

        const auto                tmp = std::filesystem::temp_directory_path() / "gr_linux_crypto4_multi_test.json";
        std::vector<std::string>  pubs(3);
        std::vector<std::string>  privs(3);
        std::vector<EVP_PKEY*>    freeList;
        for (int i = 0; i < 3; ++i) {
            Impl                      ec(C::BRAINPOOLP256R1);
            const Impl::KeyPair       kp = ec.generate_keypair();
            std::vector<std::uint8_t> pubb = Impl::serialize_public_key(kp.public_key);
            std::vector<std::uint8_t> prb  = ec.serialize_private_key(kp.private_key, "");
            pubs[static_cast<std::size_t>(i)] =
                std::string(reinterpret_cast<const char*>(pubb.data()), reinterpret_cast<const char*>(pubb.data()) + pubb.size());
            privs[static_cast<std::size_t>(i)] =
                std::string(reinterpret_cast<const char*>(prb.data()), reinterpret_cast<const char*>(prb.data()) + prb.size());
            freeList.push_back(kp.private_key);
            freeList.push_back(kp.public_key);
        }

        const std::string json = std::string("{\"AAA\":") + jsonEscapePem(pubs[0]) + ",\"BBB\":" + jsonEscapePem(pubs[1]) + ",\"CCC\":" +
                                 jsonEscapePem(pubs[2]) + "}";
        {
            std::ofstream f(tmp);
            f << json;
        }

        gnuradio4::linux_crypto::BrainpoolEciesMultiEncrypt blk;
        blk.callsign_tokens.value   = std::vector<std::string>{"AAA", "BBB", "CCC"};
        blk.key_store_path.value    = tmp.string();
        blk.curve_name.value        = Impl::curve_to_string(C::BRAINPOOLP256R1);
        blk.kdf_info.value          = std::string("gr-linux-crypto-ecies-v1");
        blk.init(std::make_shared<gr::Sequence>());
        blk.start();

        gr::MsgPortOut src;
        gr::MsgPortIn  snk;
        expect(src.connect(blk.msg_pdu_in).has_value());
        expect(blk.msg_pdu_out.connect(snk).has_value());

        std::vector<std::uint8_t> plain{'m', 'u', 'l', 't', 'i'};
        pushPdu(src, plain);
        blk.processScheduledMessages();

        auto reader = snk.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        expect(reader[0].data.has_value());
        const auto* wireTb =
            gnuradio4::linux_crypto::detail::tensorBytesFromMap(*reader[0].data, std::string_view("pdu_data"));
        expect(wireTb != nullptr);

        const std::span<const std::uint8_t> wire(wireTb->data(), wireTb->size());
        for (int i = 0; i < 3; ++i) {
            static constexpr const char* callsigns[] = {"AAA", "BBB", "CCC"};
            std::vector<std::uint8_t>     out;
            expect(gnuradio4::linux_crypto::detail::multiRecipientDecrypt(C::BRAINPOOLP256R1, std::string_view(callsigns[i]),
                std::string_view(privs[static_cast<std::size_t>(i)].data(), privs[static_cast<std::size_t>(i)].size()),
                std::string_view("gr-linux-crypto-ecies-v1"), wire, out));
            expect(std::ranges::equal(out, plain));
        }

        for (EVP_PKEY* p : freeList) {
            EVP_PKEY_free(p);
        }
        expect(reader.consume(reader.size()));
        std::error_code ec2;
        std::filesystem::remove(tmp, ec2);
    };
};

} // namespace

int main() { return boost::ut::cfg<boost::ut::override>.run(); }

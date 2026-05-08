// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/linux_crypto/detail/AfalgAesContext.hpp>

#include <array>
#include <span>
#include <vector>

using namespace boost::ut;

namespace {

const boost::ut::suite<"KernelCryptoAes Afalg"> kernelAesSuite = [] {
    skip / "AF_ALG CBC round-trip when kernel supports aes-cbc"_test = [] {
        gnuradio4::linux_crypto::detail::AfalgAesContext ctx;
        std::vector<std::uint8_t>                          key(32UZ, 0x3BU);
        std::vector<std::uint8_t>                          iv(16UZ, 0x2AU);
        if (!ctx.setParams(key, iv, std::string("cbc"), true)) {
            expect(true) << "AF_ALG unavailable; skipped";
            return;
        }

        std::array<std::uint8_t, 16> plain{};
        for (std::size_t i = 0UZ; i < plain.size(); ++i) {
            plain[i] = static_cast<std::uint8_t>(i);
        }

        std::vector<std::uint8_t> ct(plain.size());
        expect(ctx.transform(std::span<const std::uint8_t>(plain.data(), plain.size()),
            std::span<std::uint8_t>(ct.data(), ct.size()), key));
        std::vector<std::uint8_t> key2 = key;
        gnuradio4::linux_crypto::detail::AfalgAesContext dec;
        expect(dec.setParams(key2, iv, std::string("cbc"), false));
        std::vector<std::uint8_t> round(plain.size());
        expect(dec.transform(std::span<const std::uint8_t>(ct.data(), ct.size()),
            std::span<std::uint8_t>(round.data(), round.size()), key2));
        for (std::size_t i = 0UZ; i < plain.size(); ++i) {
            expect(eq(round[i], plain[i]));
        }
    };
};

} // namespace

int main() { return boost::ut::cfg<boost::ut::override>.run(); }

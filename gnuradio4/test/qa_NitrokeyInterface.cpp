// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Sequence.hpp>
#include <gnuradio-4.0/linux_crypto/NitrokeyInterface.hpp>

using namespace boost::ut;

namespace {

const boost::ut::suite<"NitrokeyInterface"> nitroSuite = [] {
    "degraded device info and empty slots without hardware"_test = [] {
        gnuradio4::linux_crypto::NitrokeyInterface blk;
        blk.init(std::make_shared<gr::Sequence>());
        blk.start();
        expect(blk.get_available_slots().empty());
        expect(!blk.get_device_info().empty());
        blk.stop();
    };
};

} // namespace

int main() { return boost::ut::cfg<boost::ut::override>.run(); }

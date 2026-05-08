// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/linux_crypto/detail/KernelKeyringDetail.hpp>

using namespace boost::ut;

namespace {

const boost::ut::suite<"KernelKeyringSource"> keyringSuite = [] {
    skip / "Kernel keyring requires a valid key_serial_t and permissions"_test = [] {
        expect(true);
    };
};

} // namespace

int main() { return boost::ut::cfg<boost::ut::override>.run(); }

// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_DETAIL_MSGPOST_HPP
#define GNURADIO4_LINUX_CRYPTO_DETAIL_MSGPOST_HPP

#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>

#include <utility>

namespace gnuradio4::linux_crypto::detail {

inline void postPropertyNotify(gr::MsgPortOut& downstream, gr::property_map body) {
    gr::Message msg;
    msg.cmd  = gr::message::Command::Notify;
    msg.data = std::move(body);
    auto w   = downstream.streamWriter().template reserve<gr::SpanReleasePolicy::ProcessAll>(1UZ);
    w[0]     = std::move(msg);
    w.publish(1UZ);
}

} // namespace gnuradio4::linux_crypto::detail

#endif

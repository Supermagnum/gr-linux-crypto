// SPDX-License-Identifier: GPL-3.0-or-later

#include <gnuradio-4.0/linux_crypto/detail/AfalgAesContext.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>

#if defined(__linux__)
#include <linux/if_alg.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

namespace gnuradio4::linux_crypto::detail {

AfalgAesContext::AfalgAesContext(AfalgAesContext&& other) noexcept
    : _configured(other._configured), _encrypt(other._encrypt), _mode(std::move(other._mode)), _iv(std::move(other._iv)),
      _localKey(std::move(other._localKey)), _sock(other._sock), _accfd(other._accfd), _heartbeat(other._heartbeat) {
    other._configured = false;
    other._sock       = -1;
    other._accfd      = -1;
}

AfalgAesContext& AfalgAesContext::operator=(AfalgAesContext&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    closeSockets();
    _configured         = other._configured;
    _encrypt            = other._encrypt;
    _mode               = std::move(other._mode);
    _iv                 = std::move(other._iv);
    _localKey           = std::move(other._localKey);
    _sock               = other._sock;
    _accfd              = other._accfd;
    _heartbeat          = other._heartbeat;
    other._configured   = false;
    other._sock         = -1;
    other._accfd        = -1;
    return *this;
}

AfalgAesContext::~AfalgAesContext() { closeSockets(); }

void AfalgAesContext::closeSockets() noexcept {
#if defined(__linux__)
    if (_accfd >= 0) {
        ::close(_accfd);
        _accfd = -1;
    }
    if (_sock >= 0) {
        ::close(_sock);
        _sock = -1;
    }
#else
    (void)this;
#endif
    _configured            = false;
    OPENSSL_cleanse(_localKey.data(), _localKey.size());
    _localKey.clear();
}

void AfalgAesContext::secureClearKeyMaterial(std::vector<std::uint8_t>& keyMaterial) noexcept {
    if (!keyMaterial.empty()) {
        OPENSSL_cleanse(keyMaterial.data(), keyMaterial.size());
    }
    keyMaterial.clear();
}

bool AfalgAesContext::unhealthy() noexcept {
#if defined(__linux__)
    if (_accfd < 0 || _sock < 0) {
        return true;
    }
    struct pollfd pfd {};
    pfd.fd     = _accfd;
    pfd.events = POLLERR | POLLHUP;
    if (::poll(&pfd, 1, 0) < 0) {
        return true;
    }
    if ((pfd.revents & (POLLERR | POLLHUP)) != 0) {
        return true;
    }
#endif
    return false;
}

void AfalgAesContext::periodicHealthCheck(std::vector<std::uint8_t>& keyMirror) noexcept {
    constexpr unsigned kPeriod = 1000U;
    ++_heartbeat;
    if ((_heartbeat % kPeriod) != 0U) {
        return;
    }
    if (_configured && unhealthy()) {
        closeSockets();
        secureClearKeyMaterial(keyMirror);
    }
}

#if defined(__linux__)

bool AfalgAesContext::bindSocket(const std::vector<std::uint8_t>& key) {
    closeSockets();

    _sock = ::socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (_sock < 0) {
        return false;
    }

    struct sockaddr_alg sa {};
    sa.salg_family = AF_ALG;
    const auto copyField = [](char* dst, std::size_t dstLen, std::string_view src) {
        const std::size_t n = std::min(dstLen - 1U, src.size());
        std::memcpy(dst, src.data(), n);
        dst[n] = '\0';
    };
    copyField(reinterpret_cast<char*>(sa.salg_type), sizeof(sa.salg_type), "skcipher");

    std::string alg_name;
    if (_mode == "cbc" || _mode == "ecb" || _mode == "ctr" || _mode == "gcm") {
        alg_name = std::string("aes-").append(_mode);
    }
    copyField(reinterpret_cast<char*>(sa.salg_name), sizeof(sa.salg_name), alg_name);

    if (::bind(_sock, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0) {
        closeSockets();
        return false;
    }

    _accfd = ::accept(_sock, nullptr, nullptr);
    if (_accfd < 0) {
        closeSockets();
        return false;
    }

    if (::setsockopt(_accfd, SOL_ALG, ALG_SET_KEY, key.data(), key.size()) < 0) {
        closeSockets();
        return false;
    }

    uint32_t op = _encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
    if (::setsockopt(_accfd, SOL_ALG, ALG_SET_OP, &op, sizeof(op)) < 0) {
        closeSockets();
        return false;
    }

    _localKey.assign(key.begin(), key.end());
    _configured = true;
    return true;
}

bool AfalgAesContext::setParams(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& iv, const std::string& mode,
    bool encrypt) {
    secureClearKeyMaterial(_localKey);
    closeSockets();

    _mode    = mode;
    _encrypt = encrypt;
    _iv.assign(iv.begin(), iv.end());

    const std::size_t ks = key.size();
    if (ks != 16UZ && ks != 24UZ && ks != 32UZ) {
        _configured = false;
        return false;
    }

    if (mode != "cbc" && mode != "ecb" && mode != "ctr" && mode != "gcm") {
        _configured = false;
        return false;
    }

    if (mode == "cbc" || mode == "ctr" || mode == "gcm") {
        if (_iv.size() != 16UZ) {
            _configured = false;
            return false;
        }
    } else if (mode == "ecb") {
        _iv.clear();
    }

    return bindSocket(key);
}

bool AfalgAesContext::kernelTransform(std::span<const std::uint8_t> in, std::span<std::uint8_t> out) noexcept {
    if (_accfd < 0 || in.size() != out.size()) {
        return false;
    }

    msghdr msg {};
    iovec  iov {};
    iov.iov_base = const_cast<std::uint8_t*>(in.data());
    iov.iov_len  = in.size();
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    std::array<unsigned char, CMSG_SPACE(sizeof(af_alg_iv))> cbuf{};
    if (!_iv.empty() && (_mode == "cbc" || _mode == "ctr" || _mode == "gcm")) {
        msg.msg_control    = cbuf.data();
        msg.msg_controllen = sizeof(cbuf);
        cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type  = ALG_SET_IV;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(af_alg_iv));
        af_alg_iv* alg_iv           = reinterpret_cast<af_alg_iv*>(CMSG_DATA(cmsg));
        alg_iv->ivlen               = _iv.size();
        std::memcpy(alg_iv->iv, _iv.data(), std::min(alg_iv->ivlen, static_cast<unsigned int>(_iv.size())));
    } else {
        msg.msg_control    = nullptr;
        msg.msg_controllen = 0;
    }

    if (::sendmsg(_accfd, &msg, 0) < 0) {
        return false;
    }

    ssize_t rr = ::recv(_accfd, out.data(), out.size(), 0);
    if (rr != static_cast<ssize_t>(out.size())) {
        return false;
    }
    return true;
}

#else

bool AfalgAesContext::setParams(const std::vector<std::uint8_t>& /*key*/, const std::vector<std::uint8_t>& /*iv*/, const std::string& /*mode*/,
    bool /*encrypt*/) {
    _configured = false;
    return false;
}

bool AfalgAesContext::kernelTransform(std::span<const std::uint8_t> /*in*/, std::span<std::uint8_t> /*out*/) noexcept { return false; }

#endif

bool AfalgAesContext::transform(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, std::vector<std::uint8_t>& keyMirror) noexcept {
    if (!_configured) {
        if (!out.empty()) {
            std::memset(out.data(), 0, out.size());
        }
        return false;
    }
    const bool ok = kernelTransform(in, out);
    if (!ok) {
        if (!out.empty()) {
            std::memset(out.data(), 0, out.size());
        }
        closeSockets();
        secureClearKeyMaterial(keyMirror);
        return false;
    }
    return true;
}

} // namespace gnuradio4::linux_crypto::detail

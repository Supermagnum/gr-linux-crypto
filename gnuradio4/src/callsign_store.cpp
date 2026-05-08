// SPDX-License-Identifier: GPL-3.0-or-later

#include <gnuradio-4.0/linux_crypto/detail/CallsignKeyStore.hpp>

#include <cctype>
#include <fstream>
#include <sstream>

namespace gnuradio4::linux_crypto::detail {

namespace {

std::string trimUpper(std::string_view s) {
    std::string r;
    for (char c : s) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            r.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
    }
    return r;
}

bool parseJsonString(const std::string& raw, std::size_t& i, std::string& out) {
    if (i >= raw.size() || raw[i] != '"') {
        return false;
    }
    ++i;
    out.clear();
    while (i < raw.size()) {
        char c = raw[i++];
        if (c == '"') {
            return true;
        }
        if (c == '\\' && i < raw.size()) {
            char e = raw[i++];
            if (e == 'n') {
                out.push_back('\n');
            } else if (e == 'r') {
                out.push_back('\r');
            } else if (e == 't') {
                out.push_back('\t');
            } else if (e == '\\' || e == '"') {
                out.push_back(e);
            } else {
                out.push_back(e);
            }
            continue;
        }
        out.push_back(c);
    }
    return false;
}

void skipWs(const std::string& raw, std::size_t& i) {
    while (i < raw.size() && std::isspace(static_cast<unsigned char>(raw[i]))) {
        ++i;
    }
}

} // namespace

bool CallsignKeyStore::loadFile(const std::string& path) {
    _keys.clear();
    _groups.clear();
    std::ifstream f(path);
    if (!f) {
        return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string raw = ss.str();
    std::size_t       i   = 0;
    skipWs(raw, i);
    if (i >= raw.size() || raw[i] != '{') {
        return false;
    }
    ++i;
    while (true) {
        skipWs(raw, i);
        if (i < raw.size() && raw[i] == '}') {
            return true;
        }
        std::string key;
        if (!parseJsonString(raw, i, key)) {
            return false;
        }
        key = trimUpper(key);
        skipWs(raw, i);
        if (i >= raw.size() || raw[i] != ':') {
            return false;
        }
        ++i;
        skipWs(raw, i);
        if (i >= raw.size()) {
            return false;
        }
        if (raw[i] == '[') {
            ++i;
            std::vector<std::string> members;
            while (true) {
                skipWs(raw, i);
                if (i < raw.size() && raw[i] == ']') {
                    ++i;
                    break;
                }
                std::string el;
                if (!parseJsonString(raw, i, el)) {
                    return false;
                }
                members.push_back(trimUpper(el));
                skipWs(raw, i);
                if (i < raw.size() && raw[i] == ',') {
                    ++i;
                    continue;
                }
                if (i < raw.size() && raw[i] == ']') {
                    ++i;
                    break;
                }
                return false;
            }
            _groups.emplace(std::move(key), std::move(members));
        } else {
            std::string val;
            if (!parseJsonString(raw, i, val)) {
                return false;
            }
            _keys.emplace(std::move(key), std::move(val));
        }
        skipWs(raw, i);
        if (i < raw.size() && raw[i] == ',') {
            ++i;
            continue;
        }
        if (i < raw.size() && raw[i] == '}') {
            return true;
        }
        return false;
    }
}

std::optional<std::string> CallsignKeyStore::publicPemForCallsign(const std::string& callsignUpper) const {
    auto it = _keys.find(callsignUpper);
    if (it == _keys.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<std::string> CallsignKeyStore::expandRecipients(const std::vector<std::string>& tokens) const {
    std::vector<std::string> out;
    for (std::string t : tokens) {
        std::string u = trimUpper(t);
        if (u.empty()) {
            continue;
        }
        auto git = _groups.find(u);
        if (git != _groups.end()) {
            out.insert(out.end(), git->second.begin(), git->second.end());
        } else {
            out.push_back(u);
        }
    }
    return out;
}

} // namespace gnuradio4::linux_crypto::detail

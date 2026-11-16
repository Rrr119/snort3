//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "doh_parser.h"

#include <algorithm>
#include <cctype>

namespace doh
{

static bool is_ascii_space(char c)
{
    return c == ' ' or c == '\t';
}

bool split_uri(std::string_view uri, UriParts& parts)
{
    parts = {};

    const size_t scheme = uri.find("://");
    size_t start = 0;
    if (scheme != std::string_view::npos)
    {
        start = uri.find('/', scheme + 3);
        if (start == std::string_view::npos)
        {
            parts.path = "/";
            return true;
        }
    }

    if (start >= uri.size() or uri[start] != '/')
        return false;

    const size_t query = uri.find('?', start);
    const size_t fragment = uri.find('#', start);
    size_t path_end = std::min(query, fragment);
    if (path_end == std::string_view::npos)
        path_end = uri.size();

    parts.path.assign(uri.substr(start, path_end - start));

    if (query != std::string_view::npos)
    {
        size_t query_end = fragment == std::string_view::npos ? uri.size() : fragment;
        parts.query.assign(uri.substr(query + 1, query_end - query - 1));
    }

    return true;
}

bool media_type_matches(std::string_view value, const std::string& expected)
{
    while (!value.empty() and is_ascii_space(value.front()))
        value.remove_prefix(1);
    while (!value.empty() and is_ascii_space(value.back()))
        value.remove_suffix(1);

    const size_t parameter = value.find(';');
    if (parameter != std::string_view::npos)
        value = value.substr(0, parameter);

    while (!value.empty() and is_ascii_space(value.back()))
        value.remove_suffix(1);

    if (value.size() != expected.size())
        return false;

    return std::equal(value.begin(), value.end(), expected.begin(),
        [](char lhs, char rhs)
        {
            return std::tolower(static_cast<unsigned char>(lhs)) ==
                std::tolower(static_cast<unsigned char>(rhs));
        });
}

bool find_dns_query_param(std::string_view query, std::string& encoded_query)
{
    encoded_query.clear();

    size_t offset = 0;
    while (offset <= query.size())
    {
        size_t end = query.find('&', offset);
        if (end == std::string_view::npos)
            end = query.size();

        const std::string_view parameter = query.substr(offset, end - offset);
        const size_t equal = parameter.find('=');
        if (equal != std::string_view::npos and parameter.substr(0, equal) == "dns")
        {
            encoded_query.assign(parameter.substr(equal + 1));
            return !encoded_query.empty();
        }

        if (end == query.size())
            break;
        offset = end + 1;
    }

    return false;
}

static int base64_value(char c)
{
    if (c >= 'A' and c <= 'Z')
        return c - 'A';
    if (c >= 'a' and c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' and c <= '9')
        return c - '0' + 52;
    if (c == '+' or c == '-')
        return 62;
    if (c == '/' or c == '_')
        return 63;
    return -1;
}

bool base64url_decode(std::string_view encoded, std::vector<uint8_t>& decoded)
{
    decoded.clear();
    decoded.reserve((encoded.size() * 3) / 4);

    uint32_t accumulator = 0;
    unsigned bits = 0;
    bool padding_seen = false;

    for (char c : encoded)
    {
        if (c == '=')
        {
            padding_seen = true;
            continue;
        }

        if (padding_seen)
            return false;

        const int value = base64_value(c);
        if (value < 0)
            return false;

        accumulator = (accumulator << 6) | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            decoded.push_back(static_cast<uint8_t>((accumulator >> bits) & 0xff));
        }
    }

    if (bits >= 6)
        return false;

    if (bits and (accumulator & ((1u << bits) - 1)))
        return false;

    return !decoded.empty();
}

static ParseStatus read_name(const uint8_t* data, size_t length, size_t& offset,
    std::string& name)
{
    name.clear();

    size_t position = offset;
    size_t end = offset;
    bool jumped = false;
    unsigned jumps = 0;
    const unsigned max_jumps = static_cast<unsigned>(std::min<size_t>(length, 128));

    while (true)
    {
        if (position >= length)
            return ParseStatus::NEED_MORE_DATA;

        const uint8_t label_length = data[position];
        if (label_length == 0)
        {
            if (!jumped)
                end = position + 1;
            offset = end;
            return name.empty() ? ParseStatus::MALFORMED : ParseStatus::OK;
        }

        if ((label_length & 0xc0) == 0xc0)
        {
            if (position + 1 >= length)
                return ParseStatus::NEED_MORE_DATA;

            if (++jumps > max_jumps)
                return ParseStatus::MALFORMED;

            const size_t pointer = (static_cast<size_t>(label_length & 0x3f) << 8) |
                data[position + 1];
            if (pointer >= length)
                return ParseStatus::MALFORMED;

            if (!jumped)
                end = position + 2;
            jumped = true;
            position = pointer;
            continue;
        }

        if (label_length & 0xc0 or label_length > 63)
            return ParseStatus::MALFORMED;

        if (position + 1 + label_length > length)
            return ParseStatus::NEED_MORE_DATA;

        if (!name.empty())
            name.push_back('.');

        for (size_t i = 0; i < label_length; ++i)
        {
            const unsigned char c = data[position + 1 + i];
            if (c < 0x21 or c > 0x7e or c == '.')
                return ParseStatus::MALFORMED;
            name.push_back(static_cast<char>(std::tolower(c)));
        }

        if (name.size() > MAX_DOMAIN_LEN)
            return ParseStatus::MALFORMED;

        position += label_length + 1;
        if (!jumped)
            end = position;
    }
}

ParseStatus parse_dns_question(const uint8_t* data, size_t length, DnsQuestion& question)
{
    question = {};

    if (!data)
        return ParseStatus::MALFORMED;

    if (length < DNS_HEADER_LEN)
        return ParseStatus::NEED_MORE_DATA;

    const uint16_t questions = (static_cast<uint16_t>(data[4]) << 8) | data[5];
    if (questions == 0)
        return ParseStatus::MALFORMED;

    size_t offset = DNS_HEADER_LEN;
    const ParseStatus status = read_name(data, length, offset, question.name);
    if (status != ParseStatus::OK)
        return status;

    if (offset + 4 > length)
        return ParseStatus::NEED_MORE_DATA;

    question.type = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
    question.dns_class = (static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3];
    return ParseStatus::OK;
}

}

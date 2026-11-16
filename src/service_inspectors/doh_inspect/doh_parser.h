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

#ifndef DOH_PARSER_H
#define DOH_PARSER_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace doh
{

constexpr size_t DNS_HEADER_LEN = 12;
constexpr size_t MAX_DOMAIN_LEN = 253;
constexpr size_t MAX_DNS_MESSAGE_LEN = 65535;

enum class ParseStatus
{
    OK,
    NEED_MORE_DATA,
    MALFORMED
};

struct DnsQuestion
{
    std::string name;
    uint16_t type = 0;
    uint16_t dns_class = 0;
};

struct UriParts
{
    std::string path;
    std::string query;
};

bool split_uri(std::string_view uri, UriParts& parts);
bool media_type_matches(std::string_view value, const std::string& expected);
bool find_dns_query_param(std::string_view query, std::string& encoded_query);
bool base64url_decode(std::string_view encoded, std::vector<uint8_t>& decoded);
ParseStatus parse_dns_question(const uint8_t* data, size_t length, DnsQuestion& question);

}

#endif

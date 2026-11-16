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

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <set>
#include <string>
#include <vector>

#include "CppUTest/TestHarness.h"

#include "service_inspectors/doh_inspect/doh_parser.h"

#ifndef DOH_PCAP_PATH
#define DOH_PCAP_PATH "doh_inspect.pcap"
#endif

using namespace doh;

static uint32_t read_u32(const uint8_t* data)
{
    return static_cast<uint32_t>(data[0]) |
        (static_cast<uint32_t>(data[1]) << 8) |
        (static_cast<uint32_t>(data[2]) << 16) |
        (static_cast<uint32_t>(data[3]) << 24);
}

static bool contains(const uint8_t* data, size_t length, const char* text)
{
    const size_t text_length = strlen(text);
    return std::search(data, data + length, text, text + text_length) != data + length;
}

TEST_GROUP(doh_pcap)
{
};

TEST(doh_pcap, extracts_get_and_post_domains)
{
    std::ifstream input(DOH_PCAP_PATH, std::ios::binary);
    CHECK_TRUE(input.good());

    const std::vector<uint8_t> pcap((std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    CHECK(pcap.size() > 24);
    CHECK(read_u32(pcap.data()) == 0xa1b2c3d4u);
    CHECK(read_u32(pcap.data() + 20) == 1u);

    std::set<std::string> domains;
    unsigned get_requests = 0;
    unsigned post_requests = 0;
    unsigned responses = 0;

    size_t offset = 24;
    while (offset + 16 <= pcap.size())
    {
        const uint32_t captured_length = read_u32(pcap.data() + offset + 8);
        offset += 16;
        if (offset + captured_length > pcap.size())
            break;

        const uint8_t* frame = pcap.data() + offset;
        offset += captured_length;

        if (captured_length < 14 + 20 or frame[12] != 0x08 or frame[13] != 0x00)
            continue;

        const uint8_t* ip = frame + 14;
        const size_t ip_header_length = (ip[0] & 0x0f) * 4;
        if (ip[9] != 6 or captured_length < 14 + ip_header_length + 20)
            continue;

        const uint8_t* tcp = ip + ip_header_length;
        const size_t tcp_header_length = (tcp[12] >> 4) * 4;
        const size_t payload_offset = 14 + ip_header_length + tcp_header_length;
        if (payload_offset >= captured_length)
            continue;

        const uint8_t* payload = frame + payload_offset;
        const size_t payload_length = captured_length - payload_offset;
        const std::string text(reinterpret_cast<const char*>(payload), payload_length);

        if (text.rfind("GET /dns-query?dns=", 0) == 0)
        {
            get_requests++;
            const size_t line_end = text.find("\r\n");
            CHECK(line_end != std::string::npos);

            const std::string request_line = text.substr(0, line_end);
            const size_t second_space = request_line.find(' ', 4);
            CHECK(second_space != std::string::npos);

            UriParts parts;
            CHECK_TRUE(split_uri(request_line.substr(4, second_space - 4), parts));
            STRCMP_EQUAL("/dns-query", parts.path.c_str());

            std::string encoded;
            CHECK_TRUE(find_dns_query_param(parts.query, encoded));

            std::vector<uint8_t> decoded;
            CHECK_TRUE(base64url_decode(encoded, decoded));

            DnsQuestion question;
            CHECK_EQUAL(ParseStatus::OK,
                parse_dns_question(decoded.data(), decoded.size(), question));
            domains.insert(question.name);
        }
        else if (text.rfind("POST /dns-query ", 0) == 0)
        {
            post_requests++;
            CHECK_TRUE(contains(payload, payload_length,
                "Content-Type: application/dns-message\r\n"));

            const size_t header_end = text.find("\r\n\r\n");
            CHECK(header_end != std::string::npos);
            if (header_end == std::string::npos)
                continue;

            const std::string headers = text.substr(0, header_end + 4);
            const size_t content_length_pos = headers.find("Content-Length: ");
            CHECK(content_length_pos != std::string::npos);
            if (content_length_pos == std::string::npos)
                continue;

            const size_t value_start = content_length_pos + strlen("Content-Length: ");
            const size_t value_end = headers.find("\r\n", value_start);
            const size_t body_length = std::stoul(headers.substr(value_start,
                value_end - value_start));

            CHECK(header_end + 4 + body_length <= payload_length);
            DnsQuestion question;
            CHECK_EQUAL(ParseStatus::OK,
                parse_dns_question(payload + header_end + 4, body_length, question));
            domains.insert(question.name);
        }
        else if (text.rfind("HTTP/1.1 200 OK\r\n", 0) == 0 and
            contains(payload, payload_length, "Content-Type: application/dns-message\r\n"))
            responses++;
    }

    UNSIGNED_LONGS_EQUAL(1, get_requests);
    UNSIGNED_LONGS_EQUAL(1, post_requests);
    UNSIGNED_LONGS_EQUAL(2, responses);
    UNSIGNED_LONGS_EQUAL(2, domains.size());
    CHECK_TRUE(domains.count("example.com"));
    CHECK_TRUE(domains.count("dns.google"));
}

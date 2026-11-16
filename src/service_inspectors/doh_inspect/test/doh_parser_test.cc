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

#include "CppUTest/TestHarness.h"

#include "service_inspectors/doh_inspect/doh_parser.h"

using namespace doh;

TEST_GROUP(doh_parser)
{
};

TEST(doh_parser, split_origin_form_uri)
{
    UriParts parts;
    CHECK_TRUE(split_uri("/dns-query?dns=abc&ct=application%2Fdns-message", parts));
    STRCMP_EQUAL("/dns-query", parts.path.c_str());
    STRCMP_EQUAL("dns=abc&ct=application%2Fdns-message", parts.query.c_str());
}

TEST(doh_parser, split_absolute_uri)
{
    UriParts parts;
    CHECK_TRUE(split_uri("https://dns.example/dns-query?dns=abc#fragment", parts));
    STRCMP_EQUAL("/dns-query", parts.path.c_str());
    STRCMP_EQUAL("dns=abc", parts.query.c_str());
}

TEST(doh_parser, reject_non_path_uri)
{
    UriParts parts;
    CHECK_FALSE(split_uri("dns-query", parts));
}

TEST(doh_parser, match_content_type_case_and_parameters)
{
    CHECK_TRUE(media_type_matches("Application/DNS-Message", "application/dns-message"));
    CHECK_TRUE(media_type_matches(" application/dns-message ; charset=binary ",
        "application/dns-message"));
    CHECK_FALSE(media_type_matches("application/dns-json", "application/dns-message"));
    CHECK_FALSE(media_type_matches("application/dns-message-extra",
        "application/dns-message"));
}

TEST(doh_parser, find_dns_parameter)
{
    std::string encoded;
    CHECK_TRUE(find_dns_query_param("foo=1&dns=EjQBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE", encoded));
    STRCMP_EQUAL("EjQBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE", encoded.c_str());

    CHECK_FALSE(find_dns_query_param("dns=&foo=1", encoded));
    CHECK_FALSE(find_dns_query_param("dns-json=abc", encoded));
}

TEST(doh_parser, decode_base64url)
{
    std::vector<uint8_t> decoded;
    CHECK_TRUE(base64url_decode("EjQBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE", decoded));

    static const uint8_t expected[] =
    {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };

    LONGS_EQUAL(sizeof(expected), decoded.size());
    MEMCMP_EQUAL(expected, decoded.data(), sizeof(expected));
}

TEST(doh_parser, decode_urlsafe_alphabet_and_padding)
{
    std::vector<uint8_t> decoded;
    CHECK_TRUE(base64url_decode("_-8=", decoded));
    LONGS_EQUAL(2, decoded.size());
    LONGS_EQUAL(0xff, decoded[0]);
    LONGS_EQUAL(0xef, decoded[1]);

    CHECK_FALSE(base64url_decode("@@@@", decoded));
    CHECK_FALSE(base64url_decode("A", decoded));
}

TEST(doh_parser, parse_dns_question)
{
    static const uint8_t query[] =
    {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0x03, 'C', 'O', 'M', 0x00,
        0x00, 0x01, 0x00, 0x01
    };

    DnsQuestion question;
    CHECK_EQUAL(ParseStatus::OK, parse_dns_question(query, sizeof(query), question));
    STRCMP_EQUAL("example.com", question.name.c_str());
    LONGS_EQUAL(1, question.type);
    LONGS_EQUAL(1, question.dns_class);
}

TEST(doh_parser, parse_compressed_name)
{
    static const uint8_t query[] =
    {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'w', 'w', 'w', 0xc0, 0x16, 0x00, 0x1c, 0x00, 0x01,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00
    };

    DnsQuestion question;
    CHECK_EQUAL(ParseStatus::OK, parse_dns_question(query, sizeof(query), question));
    STRCMP_EQUAL("www.example.com", question.name.c_str());
    LONGS_EQUAL(28, question.type);
}

TEST(doh_parser, reject_malformed_or_incomplete_dns)
{
    DnsQuestion question;
    static const uint8_t short_header[11] = {};
    CHECK_EQUAL(ParseStatus::NEED_MORE_DATA,
        parse_dns_question(short_header, sizeof(short_header), question));

    static const uint8_t no_question[DNS_HEADER_LEN] = {};
    CHECK_EQUAL(ParseStatus::MALFORMED,
        parse_dns_question(no_question, sizeof(no_question), question));

    static const uint8_t bad_label[] =
    {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 'a'
    };
    CHECK_EQUAL(ParseStatus::MALFORMED,
        parse_dns_question(bad_label, sizeof(bad_label), question));
}

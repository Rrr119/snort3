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

#ifndef DOH_EVENTS_H
#define DOH_EVENTS_H

#include <string>
#include <utility>

#include "framework/data_bus.h"

struct DohEventIds
{
    enum : unsigned
    {
        DOH_DOMAIN,
        num_ids
    };
};

const snort::PubKey doh_pub_key { "doh_inspect", DohEventIds::num_ids };

namespace snort
{

class SO_PUBLIC DohDomainEvent : public DataEvent
{
public:
    DohDomainEvent(std::string domain, uint16_t query_type, uint16_t query_class,
        std::string path, std::string content_type, std::string method, bool from_client)
        : domain(std::move(domain)), query_type(query_type), query_class(query_class),
        path(std::move(path)), content_type(std::move(content_type)),
        method(std::move(method)), from_client(from_client)
    { }

    const std::string& get_domain() const
    { return domain; }

    uint16_t get_query_type() const
    { return query_type; }

    uint16_t get_query_class() const
    { return query_class; }

    const std::string& get_path() const
    { return path; }

    const std::string& get_content_type() const
    { return content_type; }

    const std::string& get_method() const
    { return method; }

    bool is_from_client() const
    { return from_client; }

private:
    std::string domain;
    uint16_t query_type;
    uint16_t query_class;
    std::string path;
    std::string content_type;
    std::string method;
    bool from_client;
};

}

#endif

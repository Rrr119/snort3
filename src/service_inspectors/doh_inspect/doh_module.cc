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

#include "doh_module.h"

#include <cctype>
#include <utility>

#include "log/messages.h"

using namespace snort;

THREAD_LOCAL DohStats doh_stats;
THREAD_LOCAL ProfileStats doh_perf_stats;
THREAD_LOCAL const Trace* doh_trace = nullptr;

static const Parameter doh_params[] =
{
    { "paths", Parameter::PT_STRING, nullptr, "/dns-query",
      "comma-separated HTTP paths used by DoH endpoints" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo doh_pegs[] =
{
    { CountType::SUM, "requests", "DoH requests detected" },
    { CountType::SUM, "responses", "DoH responses detected" },
    { CountType::SUM, "get_requests", "DoH GET requests detected" },
    { CountType::SUM, "post_requests", "DoH POST requests detected" },
    { CountType::SUM, "domains", "unique DoH query domains extracted" },
    { CountType::SUM, "malformed_queries", "malformed DNS queries in DoH requests" },
    { CountType::SUM, "malformed_payloads", "malformed DNS payloads in DoH messages" },
    { CountType::END, nullptr, nullptr }
};

static const TraceOption doh_trace_options[] =
{
    { "doh", TRACE_DOH, "log DoH endpoints and extracted query domains" },
    { nullptr, 0, nullptr }
};

static void split_list(const Value& value, std::set<std::string>& destination)
{
    const char* input = value.get_string();
    std::string item;

    for (const char* c = input; *c; ++c)
    {
        if (*c == ',' or std::isspace(static_cast<unsigned char>(*c)))
        {
            if (!item.empty())
            {
                destination.insert(item);
                item.clear();
            }
        }
        else
            item.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(*c))));
    }

    if (!item.empty())
        destination.insert(std::move(item));
}

DohModule::DohModule() : Module(DOH_NAME, DOH_HELP, doh_params)
{ }

bool DohModule::begin(const char*, int, SnortConfig*)
{
    config = DohConfig();
    return true;
}

bool DohModule::end(const char*, int, SnortConfig*)
{
    if (config.paths.empty())
        ParseError("doh_inspect.paths must contain at least one HTTP path");

    for (const auto& path : config.paths)
    {
        if (path.empty() or path.front() != '/')
            ParseError("doh_inspect path '%s' must begin with '/'", path.c_str());
    }

    return true;
}

bool DohModule::set(const char*, Value& value, SnortConfig*)
{
    if (value.is("paths"))
    {
        config.paths.clear();
        split_list(value, config.paths);
    }

    return true;
}

const PegInfo* DohModule::get_pegs() const
{ return doh_pegs; }

PegCount* DohModule::get_counts() const
{ return reinterpret_cast<PegCount*>(&doh_stats); }

void DohModule::set_trace(const Trace* trace) const
{ doh_trace = trace; }

const TraceOption* DohModule::get_trace_options() const
{ return doh_trace_options; }

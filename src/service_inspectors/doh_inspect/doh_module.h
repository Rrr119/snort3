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

#ifndef DOH_MODULE_H
#define DOH_MODULE_H

#include <set>
#include <string>

#include "framework/module.h"
#include "profiler/profiler.h"
#include "trace/trace_api.h"

#define DOH_NAME "doh_inspect"
#define DOH_HELP "DNS over HTTPS inspector"

enum
{
    TRACE_DOH
};

struct DohConfig
{
    std::set<std::string> paths { "/dns-query" };
    std::set<std::string> content_types { "application/dns-message" };
};

struct DohStats
{
    PegCount requests;
    PegCount responses;
    PegCount get_requests;
    PegCount post_requests;
    PegCount domains;
    PegCount malformed_queries;
    PegCount malformed_payloads;
};

extern THREAD_LOCAL DohStats doh_stats;
extern THREAD_LOCAL snort::ProfileStats doh_perf_stats;
extern THREAD_LOCAL const snort::Trace* doh_trace;

class DohModule : public snort::Module
{
public:
    DohModule();

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    const DohConfig& get_config() const
    { return config; }

    const snort::PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override
    { return &doh_perf_stats; }

    snort::Usage get_usage() const override
    { return INSPECT; }

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

private:
    DohConfig config;
};

#endif

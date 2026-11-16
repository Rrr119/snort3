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

#ifndef DOH_INSPECT_H
#define DOH_INSPECT_H

#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "flow/flow_data.h"
#include "framework/inspector.h"

#include "doh_module.h"
#include "doh_parser.h"

struct DohTransactionState
{
    std::string method;
    std::string path;
    std::string content_type;
    std::set<std::string> domains;
    std::vector<uint8_t> request_body;
    std::vector<uint8_t> response_body;
    bool request_seen = false;
    bool response_seen = false;
    bool request_is_doh = false;
    bool response_is_doh = false;
    bool request_domain_recorded = false;
    bool response_domain_recorded = false;
};

class DohFlowData : public snort::FlowData
{
public:
    FLOW_DATA_SIZE_OF(DohFlowData)
    DohFlowData();

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

    DohTransactionState& get_transaction(int64_t stream_id)
    { return transactions[stream_id]; }

    void clear_transaction(int64_t stream_id)
    { transactions.erase(stream_id); }

    static unsigned inspector_id;

private:
    std::unordered_map<int64_t, DohTransactionState> transactions;
};

class DohInspector : public snort::Inspector
{
public:
    explicit DohInspector(const DohModule&);

    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;

    const DohConfig& get_config() const
    { return config; }

    void process_request_header(snort::DataEvent&, snort::Flow*);
    void process_response_header(snort::DataEvent&, snort::Flow*);
    void process_body(snort::DataEvent&, snort::Flow*);
    void process_transaction_end(snort::DataEvent&, snort::Flow*);

    static DohTransactionState* get_transaction(snort::Flow*, int64_t);
    static void clear_transaction(snort::Flow*, int64_t);

private:
    void parse_query_payload(DohTransactionState&, const uint8_t*, size_t,
        bool from_client, bool last_piece, snort::Flow*);
    void record_domain(DohTransactionState&, doh::DnsQuestion&, bool from_client,
        snort::Flow*);

    DohConfig config;
};

#endif

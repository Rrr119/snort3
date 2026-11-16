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

#include "doh_inspect.h"

#include <algorithm>
#include <cctype>

#include "flow/flow.h"
#include "framework/data_bus.h"
#include "pub_sub/doh_events.h"
#include "pub_sub/http_body_event.h"
#include "pub_sub/http_event_ids.h"
#include "pub_sub/http_events.h"
#include "pub_sub/http_transaction_end_event.h"
#include "trace/trace_api.h"

#include "doh_parser.h"

using namespace snort;

unsigned DohFlowData::inspector_id = 0;

static unsigned doh_pub_id = 0;

namespace
{

class DohHeaderHandler : public DataHandler
{
public:
    explicit DohHeaderHandler(DohInspector& inspector, bool request)
        : DataHandler(DOH_NAME), inspector(inspector), request(request)
    { }

    void handle(DataEvent& event, Flow* flow) override
    {
        if (request)
            inspector.process_request_header(event, flow);
        else
            inspector.process_response_header(event, flow);
    }

private:
    DohInspector& inspector;
    bool request;
};

class DohBodyHandler : public DataHandler
{
public:
    explicit DohBodyHandler(DohInspector& inspector)
        : DataHandler(DOH_NAME), inspector(inspector)
    { }

    void handle(DataEvent& event, Flow* flow) override
    { inspector.process_body(event, flow); }

private:
    DohInspector& inspector;
};

class DohEndHandler : public DataHandler
{
public:
    explicit DohEndHandler(DohInspector& inspector)
        : DataHandler(DOH_NAME), inspector(inspector)
    { }

    void handle(DataEvent& event, Flow* flow) override
    { inspector.process_transaction_end(event, flow); }

private:
    DohInspector& inspector;
};

bool path_matches(const DohConfig& config, const std::string& path)
{
    std::string normalized = path;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return config.paths.find(normalized) != config.paths.end();
}

bool content_type_matches(const DohConfig& config, const uint8_t* value, int32_t length)
{
    if (!value or length <= 0)
        return false;

    const std::string_view media_type(reinterpret_cast<const char*>(value),
        static_cast<size_t>(length));

    for (const auto& expected : config.content_types)
    {
        if (doh::media_type_matches(media_type, expected))
            return true;
    }

    return false;
}

std::string to_string(const uint8_t* value, int32_t length)
{
    if (!value or length <= 0)
        return {};

    return std::string(reinterpret_cast<const char*>(value), static_cast<size_t>(length));
}

void append_body(std::vector<uint8_t>& destination, const uint8_t* data, int32_t length)
{
    if (!data or length <= 0)
        return;

    if (destination.size() >= doh::MAX_DNS_MESSAGE_LEN)
        return;

    const size_t available = doh::MAX_DNS_MESSAGE_LEN - destination.size();
    const size_t amount = std::min(available, static_cast<size_t>(length));
    destination.insert(destination.end(), data, data + amount);
}

void trace_domain(const DohTransactionState& transaction, const doh::DnsQuestion& question,
    bool from_client)
{
    trace_logf(doh_trace, TRACE_DOH, nullptr,
        "DoH %s domain '%s' (type %u, class %u), path '%s', content-type '%s'\n",
        from_client ? "request" : "response", question.name.c_str(), question.type,
        question.dns_class, transaction.path.c_str(), transaction.content_type.c_str());
}

}

DohFlowData::DohFlowData() : FlowData(inspector_id)
{ }

DohInspector::DohInspector(const DohModule& module) : config(module.get_config())
{ }

bool DohInspector::configure(SnortConfig*)
{
    if (!doh_pub_id)
        doh_pub_id = DataBus::get_id(doh_pub_key);

    DataBus::subscribe(http_pub_key, HttpEventIds::REQUEST_HEADER,
        new DohHeaderHandler(*this, true));
    DataBus::subscribe(http_pub_key, HttpEventIds::RESPONSE_HEADER,
        new DohHeaderHandler(*this, false));
    DataBus::subscribe(http_pub_key, HttpEventIds::DOH_BODY,
        new DohBodyHandler(*this));
    DataBus::subscribe(http_pub_key, HttpEventIds::END_OF_TRANSACTION,
        new DohEndHandler(*this));

    return true;
}

void DohInspector::show(const SnortConfig*) const
{ }

DohTransactionState* DohInspector::get_transaction(Flow* flow, int64_t stream_id)
{
    if (!flow)
        return nullptr;

    auto* flow_data = static_cast<DohFlowData*>(flow->get_flow_data(DohFlowData::inspector_id));
    if (!flow_data)
    {
        flow_data = new DohFlowData;
        flow->set_flow_data(flow_data);
    }

    return &flow_data->get_transaction(stream_id);
}

void DohInspector::clear_transaction(Flow* flow, int64_t stream_id)
{
    if (!flow)
        return;

    auto* flow_data = static_cast<DohFlowData*>(flow->get_flow_data(DohFlowData::inspector_id));
    if (flow_data)
        flow_data->clear_transaction(stream_id);
}

void DohInspector::process_request_header(DataEvent& event, Flow* flow)
{
    Profile profile(doh_perf_stats);

    auto* http_event = static_cast<HttpEvent*>(&event);

    int32_t uri_length = 0;
    const uint8_t* uri = http_event->get_uri(uri_length);
    if (!uri or uri_length <= 0)
        return;

    doh::UriParts parts;
    if (!doh::split_uri(std::string_view(reinterpret_cast<const char*>(uri),
        static_cast<size_t>(uri_length)), parts))
        return;

    const bool path_match = path_matches(config, parts.path);

    int32_t content_type_length = 0;
    const uint8_t* content_type = http_event->get_content_type(content_type_length);
    const bool content_type_match =
        content_type_matches(config, content_type, content_type_length);

    std::string encoded_query;
    const bool has_query = doh::find_dns_query_param(parts.query, encoded_query);

    if (!path_match and !content_type_match)
        return;

    DohTransactionState* transaction =
        get_transaction(flow, http_event->get_httpx_stream_id());
    if (!transaction)
        return;

    if (transaction->request_seen)
        return;

    int32_t method_length = 0;
    const uint8_t* method = http_event->get_method(method_length);
    transaction->method = to_string(method, method_length);
    transaction->path = parts.path;
    transaction->content_type = to_string(content_type, content_type_length);
    transaction->request_seen = true;
    transaction->request_is_doh =
        (path_match and (content_type_match or has_query)) or content_type_match;

    if (!transaction->request_is_doh)
        return;

    doh_stats.requests++;
    if (transaction->method == "GET")
        doh_stats.get_requests++;
    else if (transaction->method == "POST")
        doh_stats.post_requests++;

    if (!has_query)
        return;

    std::vector<uint8_t> decoded;
    if (!doh::base64url_decode(encoded_query, decoded))
    {
        doh_stats.malformed_queries++;
        return;
    }

    doh::DnsQuestion question;
    const doh::ParseStatus status =
        doh::parse_dns_question(decoded.data(), decoded.size(), question);
    if (status != doh::ParseStatus::OK)
    {
        doh_stats.malformed_queries++;
        return;
    }

    record_domain(*transaction, question, true, flow);
}

void DohInspector::process_response_header(DataEvent& event, Flow* flow)
{
    Profile profile(doh_perf_stats);

    auto* http_event = static_cast<HttpEvent*>(&event);

    int32_t content_type_length = 0;
    const uint8_t* content_type = http_event->get_content_type(content_type_length);
    if (!content_type_matches(config, content_type, content_type_length))
        return;

    DohTransactionState* transaction =
        get_transaction(flow, http_event->get_httpx_stream_id());
    if (!transaction or transaction->response_seen)
        return;

    transaction->response_seen = true;
    transaction->response_is_doh = true;
    transaction->content_type = to_string(content_type, content_type_length);
    doh_stats.responses++;
}

void DohInspector::process_body(DataEvent& event, Flow* flow)
{
    Profile profile(doh_perf_stats);

    auto* body_event = static_cast<HttpDohBodyEvent*>(&event);

    int32_t length = 0;
    const uint8_t* data = body_event->get_body(length);
    if (!data or length <= 0)
        return;

    DohTransactionState* transaction =
        get_transaction(flow, body_event->get_httpx_stream_id());
    if (!transaction)
        return;

    const bool from_client = body_event->is_data_from_client();
    if (from_client)
    {
        if (!transaction->request_is_doh)
            return;
        append_body(transaction->request_body, data, length);
        if (!transaction->request_domain_recorded)
            parse_query_payload(*transaction, transaction->request_body.data(),
                transaction->request_body.size(), true, body_event->is_last_piece(), flow);
    }
    else
    {
        if (!transaction->response_is_doh)
            return;
        append_body(transaction->response_body, data, length);
        if (!transaction->response_domain_recorded)
            parse_query_payload(*transaction, transaction->response_body.data(),
                transaction->response_body.size(), false, body_event->is_last_piece(), flow);
    }
}

void DohInspector::process_transaction_end(DataEvent& event, Flow* flow)
{
    auto* transaction_end = static_cast<HttpTransactionEndEvent*>(&event);
    clear_transaction(flow, transaction_end->get_httpx_stream_id());
}

void DohInspector::parse_query_payload(DohTransactionState& transaction,
    const uint8_t* data, size_t length, bool from_client, bool last_piece, Flow* flow)
{
    if (!data or length < doh::DNS_HEADER_LEN)
    {
        if (last_piece and length)
        {
            bool& recorded = from_client ? transaction.request_domain_recorded :
                transaction.response_domain_recorded;
            recorded = true;
            doh_stats.malformed_payloads++;
        }
        return;
    }

    doh::DnsQuestion question;
    const doh::ParseStatus status = doh::parse_dns_question(data, length, question);
    if (status == doh::ParseStatus::NEED_MORE_DATA)
    {
        if (last_piece)
        {
            bool& recorded = from_client ? transaction.request_domain_recorded :
                transaction.response_domain_recorded;
            recorded = true;
            doh_stats.malformed_payloads++;
        }
        return;
    }

    bool& recorded = from_client ? transaction.request_domain_recorded :
        transaction.response_domain_recorded;

    if (status == doh::ParseStatus::MALFORMED)
    {
        recorded = true;
        doh_stats.malformed_payloads++;
        return;
    }

    recorded = true;
    record_domain(transaction, question, from_client, flow);
}

void DohInspector::record_domain(DohTransactionState& transaction,
    doh::DnsQuestion& question, bool from_client, Flow* flow)
{
    if (question.name.empty())
        return;

    if (!transaction.domains.insert(question.name).second)
        return;

    doh_stats.domains++;

    DohDomainEvent doh_event(question.name, question.type, question.dns_class,
        transaction.path, transaction.content_type, transaction.method, from_client);
    DataBus::publish(doh_pub_id, DohEventIds::DOH_DOMAIN, doh_event, flow);

    trace_domain(transaction, question, from_client);
}

//-------------------------------------------------------------------------
// API
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new DohModule; }

static void mod_dtor(Module* module)
{ delete module; }

static Inspector* doh_ctor(Module* module)
{
    return new DohInspector(*static_cast<DohModule*>(module));
}

static void doh_dtor(Inspector* inspector)
{ delete inspector; }

static void doh_init()
{ DohFlowData::init(); }

static const InspectApi doh_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        PLUGIN_SO_RELOAD,
        API_OPTIONS,
        DOH_NAME,
        DOH_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__TCP,
    nullptr,
    nullptr,
    doh_init,
    nullptr,
    nullptr,
    nullptr,
    doh_ctor,
    doh_dtor,
    nullptr,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &doh_api.base,
    nullptr
};
#else
const BaseApi* sin_doh[] =
{
    &doh_api.base,
    nullptr
};
#endif

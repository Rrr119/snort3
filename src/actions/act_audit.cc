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
// act_audit.cc

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "framework/ips_action.h"
#include "framework/module.h"
#include "protocols/packet.h"

using namespace snort;

#define action_name "audit"
#define action_help \
    "log the current packet without generating an alert"

#define module_name "audit"
#define module_help \
    "manage the counters for the audit action"

static THREAD_LOCAL struct AuditStats
{
    PegCount audit;
} audit_stats;

const PegInfo audit_pegs[] =
{
    { CountType::SUM, "audit", "number of packets that matched an IPS audit rule" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
class AuditAction : public IpsAction
{
public:
    AuditAction() : IpsAction(action_name, nullptr) { }

    void exec(Packet*, const ActInfo&) override;
};

void AuditAction::exec(Packet* p, const ActInfo& ai)
{
    if ( log_it(ai) )
    {
        log(p, ai);
        ++audit_stats.audit;
    }
}

//-------------------------------------------------------------------------
class AuditActionModule : public Module
{
public:
    AuditActionModule() : Module(module_name, module_help)
    { register_action_pegs(module_name, audit_pegs); }

    bool stats_are_aggregated() const override
    { return true; }

    void show_stats() override { }

    const PegInfo* get_pegs() const override
    { return audit_pegs; }

    PegCount* get_counts() const override
    { return reinterpret_cast<PegCount*>(&audit_stats); }
};

//-------------------------------------------------------------------------
static Module* mod_ctor()
{ return new AuditActionModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsAction* audit_ctor(Module*)
{ return new AuditAction; }

static void audit_dtor(IpsAction* p)
{ delete p; }

static ActionApi audit_api
{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        action_name,
        action_help,
        mod_ctor,
        mod_dtor,
    },
    IpsAction::IAP_LOG,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    audit_ctor,
    audit_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* act_audit[] =
#endif
{
    &audit_api.base,
    nullptr
};

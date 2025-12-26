#include "pcap_duckdb_extension.hpp"

#include "duckdb/planner/expression/bound_comparison_expression.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/planner/table_filter.hpp"
#include "duckdb/planner/filter/in_filter.hpp"
#include "duckdb/planner/filter/optional_filter.hpp"

#if DUCKDB_HAS_EXTENSION_LOADER == 0
#include "duckdb/main/extension_util.hpp"
#endif

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

namespace duckdb {

/* ---------------------------------------------------------
   Column indexes (packets table)
--------------------------------------------------------- */
enum {
    COL_TS = 0,
    COL_IFACE,
    COL_SRC_IP,
    COL_DST_IP,
    COL_SRC_PORT,
    COL_DST_PORT,
    COL_PROTOCOL,
    COL_LENGTH,
    COL_TCP_FLAGS,
    COL_TCP_SEQ,
    COL_TCP_ACK,
    COL_TCP_WINDOW
};

// ===================== VLAN SUPPORT =====================
#define ETHERTYPE_VLAN 0x8100

static uint16_t ParseEtherType(const u_char *&ptr) {
    uint16_t ethertype = ntohs(*(uint16_t *)(ptr + 12));
    ptr += 14;

    if (ethertype == ETHERTYPE_VLAN) {
        ethertype = ntohs(*(uint16_t *)(ptr + 2));
        ptr += 4;
    }
    return ethertype;
}

/* ---------------------------------------------------------
   Global State
--------------------------------------------------------- */
struct PcapPacketsGlobalState : public GlobalTableFunctionState {
    pcap_t *handle = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
};

/* ---------------------------------------------------------
   BPF Builder (selective pushdown)
--------------------------------------------------------- */
struct BpfBuilder {
    vector<string> terms;

    void Add(const string &t) { terms.push_back(t); }

    string Build() const {
        if (terms.empty()) return "";
        return StringUtil::Join(terms, " and ");
    }
};

// ===================== BPF PUSH IN =====================
static void TryBuildBpf(const vector<PcapFilter> &filters, BpfBuilder &bpf) {
    for (auto &f : filters) {
        if (f.type == ExpressionType::COMPARE_IN) {
            auto list = ListValue::GetChildren(f.value);
            vector<string> ors;
            for (auto &v : list) {
                ors.push_back("src port " + v.ToString());
            }
            bpf.Add("(" + StringUtil::Join(ors, " or ") + ")");
            continue;
        }

        if (f.type != ExpressionType::COMPARE_EQUAL) continue;

        switch (f.column_index) {
        case COL_PROTOCOL:
            if (StringUtil::Lower(f.value.GetValue<string>()) == "tcp")
                bpf.Add("(tcp or tcp6)");
            break;
        case COL_SRC_PORT:
            bpf.Add("src port " + f.value.ToString());
            break;
        case COL_DST_PORT:
            bpf.Add("dst port " + f.value.ToString());
            break;
        }
    }
}

/* ---------------------------------------------------------
   DuckDB-side filter evaluation (authoritative)
--------------------------------------------------------- */
static bool ApplyFilters(const PcapPacketsBindData &bind,
                         const ParsedPacket &pkt) {

    for (auto &f : bind.pushed_filters) {
        Value v;

        switch (bind.column_ids[f.column_index]) {
        case COL_TS: v = Value::TIMESTAMP(pkt.ts); break;
        case COL_SRC_IP: v = Value(pkt.src_ip); break;
        case COL_DST_IP: v = Value(pkt.dst_ip); break;
        case COL_SRC_PORT: v = Value::INTEGER(pkt.src_port); break;
        case COL_DST_PORT: v = Value::INTEGER(pkt.dst_port); break;
        case COL_PROTOCOL:
            v = Value(pkt.protocol == IPPROTO_TCP ? "TCP" :
                      pkt.protocol == IPPROTO_UDP ? "UDP" : "OTHER");
            break;
        case COL_LENGTH: v = Value::INTEGER(pkt.length); break;
        default: continue;
        }
        // printf("p: %s, f: %s\n", v.ToString().c_str(), f.value.ToString().c_str());
        bool match = true;
        switch (f.type) {
        case ExpressionType::COMPARE_EQUAL: match = (v == f.value); break;
        case ExpressionType::COMPARE_NOTEQUAL: match = (v != f.value); break;
        case ExpressionType::COMPARE_LESSTHAN: match = (v < f.value); break;
        case ExpressionType::COMPARE_GREATERTHAN: match = (v > f.value); break;
        case ExpressionType::COMPARE_LESSTHANOREQUALTO: match = (v <= f.value); break;
        case ExpressionType::COMPARE_GREATERTHANOREQUALTO: match = (v >= f.value); break;
        default: break;
        }

        if (!match) return false;
    }
    return true;
}

/* ---------------------------------------------------------
   Bind
--------------------------------------------------------- */
static unique_ptr<FunctionData>
PcapPacketsBind(ClientContext &, TableFunctionBindInput &input,
                vector<LogicalType> &types,
                vector<string> &names) {

    if (input.inputs.empty()) {
        throw InvalidInputException("read_pcap_packets(filename) required");
    }

    auto bind = make_uniq<PcapPacketsBindData>();
    bind->filename = input.inputs[0].GetValue<string>();

    names = {
        "ts",
        "interface_id",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "length",
        "tcp_flags",
        "tcp_seq",
        "tcp_ack",
        "tcp_window"
    };

    types = {
        LogicalType::TIMESTAMP,   // ts
        LogicalType::INTEGER,     // interface_id
        LogicalType::VARCHAR,     // src_ip
        LogicalType::VARCHAR,     // dst_ip
        LogicalType::INTEGER,     // src_port
        LogicalType::INTEGER,     // dst_port
        LogicalType::VARCHAR,     // protocol
        LogicalType::INTEGER,     // length
        LogicalType::INTEGER,     // tcp_flags
        LogicalType::BIGINT,      // tcp_seq
        LogicalType::BIGINT,      // tcp_ack
        LogicalType::INTEGER      // tcp_window
    };

    return std::move(bind);
}

/* ---------------------------------------------------------
   Init
--------------------------------------------------------- */
static unique_ptr<GlobalTableFunctionState>
PcapPacketsInit(ClientContext &, TableFunctionInitInput &input) {

    auto state = make_uniq<PcapPacketsGlobalState>();
    auto &bind = (PcapPacketsBindData &)*input.bind_data;

    if (input.filters) {
        auto &filters_map = input.filters->filters;
        for (auto it = filters_map.begin(); it != filters_map.end(); ) {
            idx_t col_idx = it->first;
            auto &filter = it->second;

            PcapFilter pf;
            pf.column_index = col_idx;
            // printf("col_idx: %d, filter_type: %d,", col_idx, filter->filter_type);

            TableFilter* current_filter = filter.get();
            while (current_filter->filter_type == TableFilterType::OPTIONAL_FILTER) {
                current_filter = static_cast<OptionalFilter &>(*current_filter).child_filter.get();
            }

            // 2. PROCESS: Handle the core filter type
            if (current_filter->filter_type == TableFilterType::CONSTANT_COMPARISON) {
                auto &constant_filter = static_cast<ConstantFilter &>(*current_filter);
                pf.type = constant_filter.comparison_type;
                pf.value = constant_filter.constant;
                bind.pushed_filters.push_back(std::move(pf));
            } 
            else if (current_filter->filter_type == TableFilterType::CONJUNCTION_AND) {
                auto &and_filter = static_cast<ConjunctionAndFilter &>(*current_filter);
                for (auto &child : and_filter.child_filters) {
                    // Check if children of AND are constants
                    if (child->filter_type == TableFilterType::CONSTANT_COMPARISON) {
                        PcapFilter pf_and;
                        pf_and.column_index = col_idx;
                        auto &constant_child = static_cast<ConstantFilter &>(*child);
                        pf_and.type = constant_child.comparison_type;
                        pf_and.value = constant_child.constant;
                        bind.pushed_filters.push_back(std::move(pf_and));
                    }
                    // Note: If AND contains nested OPTIONALs or ORs, 
                    // you might need a recursive call here.
                }
            }
            else if (current_filter->filter_type == TableFilterType::CONJUNCTION_OR) {
                auto &or_filter = static_cast<ConjunctionOrFilter &>(*current_filter);
                pf.type = ExpressionType::COMPARE_IN;
                vector<Value> in_values;
                for (auto &child : or_filter.child_filters) {
                    if (child->filter_type == TableFilterType::CONSTANT_COMPARISON) {
                        in_values.push_back(static_cast<ConstantFilter &>(*child).constant);
                    }
                }
                pf.value = Value::LIST(LogicalType::ANY, in_values);
                bind.pushed_filters.push_back(std::move(pf));
            }
            else if (current_filter->filter_type == TableFilterType::IN_FILTER) {
                auto &in_filter = static_cast<InFilter &>(*current_filter);
                pf.type = ExpressionType::COMPARE_IN;
                pf.value = Value::LIST(LogicalType::ANY, in_filter.values);
                bind.pushed_filters.push_back(std::move(pf));
            }
            else if (current_filter->filter_type == TableFilterType::IS_NULL) {
                pf.type = ExpressionType::OPERATOR_IS_NULL;
                bind.pushed_filters.push_back(std::move(pf));
            }
            else if (current_filter->filter_type == TableFilterType::IS_NOT_NULL) {
                pf.type = ExpressionType::OPERATOR_IS_NOT_NULL;
                bind.pushed_filters.push_back(std::move(pf));
            }
            else {
                // Not a filter type we handle yet
                ++it;
                continue;
            }
            // printf("applied\n");
            it = filters_map.erase(it);
        }
    }

    bind.column_ids = input.column_ids;

    /* open pcap */
    state->handle =
        pcap_open_offline(bind.filename.c_str(), state->errbuf);
    if (!state->handle) {
        throw duckdb::IOException("pcap_open_offline failed: {}", state->errbuf);
    }

    /* BPF pushdown */
    BpfBuilder bpf;
    TryBuildBpf(bind.pushed_filters, bpf);

    auto expr = bpf.Build();
    if (!expr.empty()) {
        bpf_program prog;
        if (pcap_compile(state->handle, &prog, expr.c_str(), 1,
                         PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(state->handle, &prog);
            pcap_freecode(&prog);
        }
    }

    return std::move(state);
}

// ===================== SCAN =====================
static void PcapPacketsScan(ClientContext &, TableFunctionInput &input, DataChunk &output) {

    auto &state = (PcapPacketsGlobalState &)*input.global_state;
    auto &bind = (PcapPacketsBindData &)*input.bind_data;

    idx_t out = 0;
    struct pcap_pkthdr *hdr;
    const u_char *data;

    while (out < STANDARD_VECTOR_SIZE &&
           pcap_next_ex(state.handle, &hdr, &data) == 1) {

        ParsedPacket pkt;
        pkt.ts = Timestamp::FromEpochSeconds(hdr->ts.tv_sec);
        pkt.length = hdr->len;

        const u_char *ptr = data;
        uint16_t ethertype = ParseEtherType(ptr);

        if (ethertype == ETHERTYPE_IPV6) {
            auto ip6 = (struct ip6_hdr *)ptr;
            pkt.protocol = ip6->ip6_nxt;

            char buf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6->ip6_src, buf, sizeof(buf));
            pkt.src_ip = buf;
            inet_ntop(AF_INET6, &ip6->ip6_dst, buf, sizeof(buf));
            pkt.dst_ip = buf;

            ptr += sizeof(ip6_hdr);
        } 
        else if (ethertype == ETHERTYPE_IP) {
            auto ip = (struct ip *)ptr;
            pkt.protocol = ip->ip_p;

            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf));
            pkt.src_ip = buf;
            inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf));
            pkt.dst_ip = buf;

            ptr += ip->ip_hl * 4;
        } else {
            continue;
        }

        if (pkt.protocol == IPPROTO_TCP) {
            auto tcp = (tcphdr *)ptr;
            pkt.src_port = ntohs(tcp->th_sport);
            pkt.dst_port = ntohs(tcp->th_dport);
            pkt.tcp_flags = tcp->th_flags;
            pkt.tcp_seq = ntohl(tcp->th_seq);
            pkt.tcp_ack = ntohl(tcp->th_ack);
            pkt.tcp_window = ntohs(tcp->th_win);
        } else if (pkt.protocol == IPPROTO_UDP) {
            auto udp = (udphdr *)ptr;
            pkt.src_port = ntohs(udp->uh_sport);
            pkt.dst_port = ntohs(udp->uh_dport);
        }

        if (!ApplyFilters(bind, pkt)) continue;

        for (idx_t c = 0; c < bind.column_ids.size(); c++) {
            switch (bind.column_ids[c]) {
            case COL_TS: output.SetValue(c, out, Value::TIMESTAMP(pkt.ts)); break;
            case COL_IFACE: output.SetValue(c, out, Value::INTEGER(pkt.interface_id)); break;
            case COL_SRC_IP: output.SetValue(c, out, pkt.src_ip); break;
            case COL_DST_IP: output.SetValue(c, out, pkt.dst_ip); break;
            case COL_SRC_PORT: output.SetValue(c, out, pkt.src_port); break;
            case COL_DST_PORT: output.SetValue(c, out, pkt.dst_port); break;
            case COL_PROTOCOL:
                output.SetValue(c, out,
                    pkt.protocol == IPPROTO_TCP ? "TCP" :
                    pkt.protocol == IPPROTO_UDP ? "UDP" : "OTHER");
                break;
            case COL_LENGTH: output.SetValue(c, out, Value::INTEGER(pkt.length)); break;
            case COL_TCP_FLAGS: output.SetValue(c, out, pkt.tcp_flags); break;
            case COL_TCP_SEQ: output.SetValue(c, out, (int64_t)pkt.tcp_seq); break;
            case COL_TCP_ACK: output.SetValue(c, out, (int64_t)pkt.tcp_ack); break;
            case COL_TCP_WINDOW: output.SetValue(c, out, pkt.tcp_window); break;
            }
        }
        out++;
    }

    output.SetCardinality(out);
}

/* ---------------------------------------------------------
   Load
--------------------------------------------------------- */
static TableFunction CreatePcapFunction() {
    TableFunction tf(
        "read_pcap_packets",
        {LogicalType::VARCHAR},
        PcapPacketsScan,
        PcapPacketsBind,
        PcapPacketsInit);

    tf.filter_pushdown = true;
    tf.projection_pushdown = true;

    return tf;
}

#if DUCKDB_HAS_EXTENSION_LOADER

static void LoadInternal(ExtensionLoader &loader) {
    auto read_func = CreatePcapFunction();
    loader.RegisterFunction(read_func);
}

void PcapDuckdbExtension::Load(ExtensionLoader &loader) {
    LoadInternal(loader);
}

#else  // DuckDB 1.3.x

void PcapDuckdbExtension::LoadInternal(DuckDB &db) {
    auto read_func = CreatePcapFunction();
    ExtensionUtil::RegisterFunction(*db.instance, read_func);
}

#endif

std::string PcapDuckdbExtension::Version() const {
#ifdef EXT_VERSION_PCAP_DUCKDB
	return EXT_VERSION_PCAP_DUCKDB;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

#if DUCKDB_HAS_EXTENSION_LOADER

DUCKDB_CPP_EXTENSION_ENTRY(pcap_duckdb, loader) {
	duckdb::LoadInternal(loader);
}

#else

DUCKDB_EXTENSION_API void pcap_duckdb_init(duckdb::DuckDB *db) {
    static duckdb::PcapDuckdbExtension ext;
    ext.Load(*db);
}

#endif

DUCKDB_EXTENSION_API const char *pcap_duckdb_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

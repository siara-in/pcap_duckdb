#include "pcap_duckdb_extension.hpp"

#include "duckdb/main/extension_util.hpp"
#include "duckdb/planner/table_filter.hpp"
#include "duckdb/planner/filter/optional_filter.hpp"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

using namespace duckdb;

/* ---------------------------------------------------------
   Column indexes (packets table)
--------------------------------------------------------- */
enum {
    COL_TS = 0,
    COL_SRC_IP,
    COL_DST_IP,
    COL_SRC_PORT,
    COL_DST_PORT,
    COL_PROTOCOL,
    COL_LENGTH
};

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

static void TryBuildBpf(const vector<PcapFilter> &filters, BpfBuilder &bpf) {
    for (auto &f : filters) {
        if (f.type != ExpressionType::COMPARE_EQUAL) {
            continue;
        }

        switch (f.column_index) {
        case COL_PROTOCOL: {
            auto p = StringUtil::Lower(f.value.GetValue<string>());
            if (p == "tcp") bpf.Add("(tcp or tcp6)");
            else if (p == "udp") bpf.Add("(udp or udp6)");
            break;
        }
        case COL_SRC_PORT:
            bpf.Add("src port " + f.value.ToString());
            break;
        case COL_DST_PORT:
            bpf.Add("dst port " + f.value.ToString());
            break;
        case COL_SRC_IP:
            bpf.Add("src host " + f.value.GetValue<string>());
            break;
        case COL_DST_IP:
            bpf.Add("dst host " + f.value.GetValue<string>());
            break;
        default:
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
print("p: %s, f: %s\n", v.ToString().c_str(), f.value.ToString().c_str());
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
        "ts", "src_ip", "dst_ip",
        "src_port", "dst_port",
        "protocol", "length"
    };

    types = {
        LogicalType::TIMESTAMP,
        LogicalType::VARCHAR,
        LogicalType::VARCHAR,
        LogicalType::INTEGER,
        LogicalType::INTEGER,
        LogicalType::VARCHAR,
        LogicalType::INTEGER
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

    /* collect pushed filters */
    if (input.filters) {
        for (auto it = input.filters->filters.begin();
             it != input.filters->filters.end();) {

            auto &filter = it->second;
            if (filter->filter_type == TableFilterType::CONSTANT_COMPARISON) {
                auto &cf = (ConstantFilter &)*filter;
                bind.pushed_filters.push_back(
                    {it->first, cf.comparison_type, cf.constant});
                it = input.filters->filters.erase(it);
            } else {
                ++it;
            }
        }
    }

    bind.column_ids = input.column_ids;

    /* open pcap */
    state->handle =
        pcap_open_offline(bind.filename.c_str(), state->errbuf);
    if (!state->handle) {
        throw IOException("pcap_open_offline failed: %s", state->errbuf);
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

/* ---------------------------------------------------------
   Scan
--------------------------------------------------------- */
static void
PcapPacketsScan(ClientContext &, TableFunctionInput &input,
                DataChunk &output) {

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

        // Ensure we don't overflow if the packet is tiny
        if (hdr->len < 14) continue;

        uint16_t ethertype = ntohs(*(uint16_t *)(data + 12));
        const u_char *l3 = data + 14;

        if (ethertype == ETHERTYPE_IPV6) {
            auto ip6 = (struct ip6_hdr *)l3; // Use 'struct' keyword to avoid ambiguity
            pkt.is_ipv6 = true;
            pkt.protocol = ip6->ip6_nxt;

            char buf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6->ip6_src, buf, sizeof(buf));
            pkt.src_ip = buf;
            inet_ntop(AF_INET6, &ip6->ip6_dst, buf, sizeof(buf));
            pkt.dst_ip = buf;

            l3 += sizeof(struct ip6_hdr);
        } else if (ethertype == 0x0800) { // 0x0800 is ETHERTYPE_IP
            // Renamed 'ip' to 'iph' to avoid collision with 'struct ip'
            auto iph = (struct ip *)l3; 
            pkt.is_ipv6 = false;
            pkt.protocol = iph->ip_p;

            pkt.src_ip = inet_ntoa(iph->ip_src);
            pkt.dst_ip = inet_ntoa(iph->ip_dst);

            l3 += iph->ip_hl * 4;
        } else {
            continue; // Skip non-IP traffic
        }

        if (pkt.protocol == IPPROTO_TCP) {
            auto tcp = (tcphdr *)l3;
            pkt.src_port = ntohs(tcp->th_sport);
            pkt.dst_port = ntohs(tcp->th_dport);
        } else if (pkt.protocol == IPPROTO_UDP) {
            auto udp = (udphdr *)l3;
            pkt.src_port = ntohs(udp->uh_sport);
            pkt.dst_port = ntohs(udp->uh_dport);
        } else {
            pkt.src_port = pkt.dst_port = 0;
        }

        if (!ApplyFilters(bind, pkt)) {
            continue;
        }

        for (idx_t c = 0; c < bind.column_ids.size(); c++) {
            switch (bind.column_ids[c]) {
            case COL_TS: output.SetValue(c, out, Value::TIMESTAMP(pkt.ts)); break;
            case COL_SRC_IP: output.SetValue(c, out, pkt.src_ip); break;
            case COL_DST_IP: output.SetValue(c, out, pkt.dst_ip); break;
            case COL_SRC_PORT: output.SetValue(c, out, Value::INTEGER(pkt.src_port)); break;
            case COL_DST_PORT: output.SetValue(c, out, Value::INTEGER(pkt.dst_port)); break;
            case COL_PROTOCOL:
                output.SetValue(c, out,
                    pkt.protocol == IPPROTO_TCP ? "TCP" :
                    pkt.protocol == IPPROTO_UDP ? "UDP" : "OTHER");
                break;
            case COL_LENGTH:
                output.SetValue(c, out, Value::INTEGER(pkt.length));
                break;
            }
        }
        out++;
    }

    output.SetCardinality(out);
}

/* ---------------------------------------------------------
   Load
--------------------------------------------------------- */
void PcapDuckdbExtension::Load(DuckDB &db) {
    TableFunction tf(
        "read_pcap_packets",
        {LogicalType::VARCHAR},
        PcapPacketsScan,
        PcapPacketsBind,
        PcapPacketsInit);

    tf.filter_pushdown = true;
    tf.projection_pushdown = true;

    ExtensionUtil::RegisterFunction(*db.instance, tf);
}

/* ---------------------------------------------------------
   Entry points
--------------------------------------------------------- */
extern "C" {

DUCKDB_EXTENSION_API void pcap_duckdb_init(duckdb::DuckDB *db) {
    static PcapDuckdbExtension ext;
    ext.Load(*db);
}

DUCKDB_EXTENSION_API const char *pcap_duckdb_version() {
    return "0.1.0";
}

}

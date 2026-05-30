#pragma once

#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/common/types.hpp"

#include <string>
#include <vector>

namespace duckdb {

/* ---------------------------------------------------------
   Parsed Packet (IPv4 + IPv6)
--------------------------------------------------------- */
struct ParsedPacket {
    timestamp_t ts;
    int interface_id = 0;
    bool is_ipv6 = false;
    uint8_t protocol = 0;
    string src_ip;
    string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t length = 0;

    uint8_t tcp_flags = 0;
    uint32_t tcp_seq = 0;
    uint32_t tcp_ack = 0;
    uint16_t tcp_window = 0;
};

/* ---------------------------------------------------------
   Filter info (DuckDB → BPF / eval)
--------------------------------------------------------- */
struct PcapFilter {
    idx_t column_index;
    ExpressionType type;
    Value value;

    bool operator==(const PcapFilter &o) const {
        return column_index == o.column_index &&
               type == o.type &&
               value == o.value;
    }
};

/* ---------------------------------------------------------
   Bind Data
--------------------------------------------------------- */
struct PcapPacketsBindData : public FunctionData {
    string filename;
    vector<PcapFilter> pushed_filters;
    vector<column_t> column_ids;

    unique_ptr<FunctionData> Copy() const override {
        return make_uniq<PcapPacketsBindData>(*this);
    }

    bool Equals(const FunctionData &other) const override {
        auto &o = (const PcapPacketsBindData &)other;
        return filename == o.filename &&
               pushed_filters == o.pushed_filters &&
               column_ids == o.column_ids;
    }
};

/* ---------------------------------------------------------
   Extension
--------------------------------------------------------- */
class PcapDuckdbExtension : public Extension {
public:
	void Load(duckdb::ExtensionLoader &loader) override;
    std::string Name() override { return "pcap_duckdb"; }
	std::string Version() const override;
};

} // namespace duckdb

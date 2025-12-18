#pragma once

#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/common/types.hpp"

#include <pcap.h>
#include <string>
#include <vector>

namespace duckdb {

/* ---------------------------------------------------------
   Parsed Packet (IPv4 + IPv6)
--------------------------------------------------------- */
struct ParsedPacket {
    timestamp_t ts;
    bool is_ipv6;

    string src_ip;
    string dst_ip;

    uint16_t src_port;
    uint16_t dst_port;

    uint8_t protocol; // IPPROTO_*
    uint32_t length;
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
class PcapDuckdb : public Extension {
public:
    void Load(DuckDB &db) override;
    string Name() override { return "pcap_duckdb"; }
};

} // namespace duckdb

#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t ihl_:4, // Internet Header Length
        version_:4; // Version
    uint8_t tos_; // Type of Service
    uint16_t tot_len_; // Total Length
    uint16_t id_; // Identification
    uint16_t frag_off_; // Fragment Offset
    uint8_t ttl_; // Time to Live
    uint8_t protocol_; // Protocol
    uint16_t check_; // Header Checksum
    Ip sip_; // Source Address
    Ip dip_; // Destination Address

    uint8_t version() { return version_; }
    uint8_t ihl() { return ihl_ * 4; } // ihl_는 32비트 워드 단위이므로, 바이트로 변환
    uint8_t tos() { return tos_; }
    uint16_t tot_len() { return ntohs(tot_len_); }
    uint16_t id() { return ntohs(id_); }
    uint16_t frag_off() { return ntohs(frag_off_); }
    uint8_t ttl() { return ttl_; }
    uint8_t protocol() { return protocol_; }
    uint16_t check() { return ntohs(check_); }
    uint32_t saddr() { return ntohl(sip_); }
    uint32_t daddr() { return ntohl(dip_); }
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)

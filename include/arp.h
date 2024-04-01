#ifndef ARP_H
#define ARP_H
#include <map>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct arpRequestData{
    Ip findIp;
    Mac findMac;
    pcap_t* handle;
};

EthArpPacket makeArpBRequestPacket(Mac sMac, Ip sIp, Ip tIp);
EthArpPacket makeArpURequestPacket(Mac sMac, Mac tMac, Ip sIp, Ip tIp);
bool checkArp(std::map<Ip, Ip> spoofTable, const u_char* pkt_data, Ip& sip, Ip& tip);
Mac getSenderMac(const u_char* pkt_data);
Mac findMac(pcap_t* handle, std::map<Ip, Mac> arpTable, Ip fip, Mac myMac, Ip myIp);
bool sendArpURequest(pcap_t* handle, Mac sMac, Mac tMac, Ip sIp, Ip tIp);
#endif // ARP_H

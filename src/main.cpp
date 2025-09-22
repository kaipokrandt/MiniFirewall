#include <iostream>
#include <pcap.h>
#include "packet.hpp"
#include "logger.hpp"
#include "firewall.hpp"

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    ParsedPacket pkt = parse_packet(packet, header->len);
    Firewall* fw = reinterpret_cast<Firewall*>(user);
    if (fw->check_packet(pkt)) {
        log_packet(pkt);
    } else {
        std::cout << "[BLOCKED] Packet from " << pkt.src_ip << " to " << pkt.dst_ip << std::endl;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <rules_file>" << std::endl;
        return 1;
    }

    Firewall fw;
    if (!fw.load_rules(argv[2])) return 1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device " << argv[1] << ": " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Listening on " << argv[1] << "..." << std::endl;
    pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&fw));
    pcap_close(handle);
    return 0;
}

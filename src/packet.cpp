#include "packet.hpp"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

ParsedPacket parse_packet(const unsigned char* packet, size_t len) {
    ParsedPacket parsed{};
    parsed.length = len;

    const struct ip* iphdr = reinterpret_cast<const struct ip*>(packet + 14);
    parsed.src_ip = inet_ntoa(iphdr->ip_src);
    parsed.dst_ip = inet_ntoa(iphdr->ip_dst);

    if (iphdr->ip_p == IPPROTO_TCP) {
        parsed.protocol = "TCP";
        const struct tcphdr* tcph = reinterpret_cast<const struct tcphdr*>(packet + 14 + iphdr->ip_hl * 4);
        parsed.src_port = ntohs(tcph->th_sport);
        parsed.dst_port = ntohs(tcph->th_dport);
    } else if (iphdr->ip_p == IPPROTO_UDP) {
        parsed.protocol = "UDP";
        const struct udphdr* udph = reinterpret_cast<const struct udphdr*>(packet + 14 + iphdr->ip_hl * 4);
        parsed.src_port = ntohs(udph->uh_sport);
        parsed.dst_port = ntohs(udph->uh_dport);
    } else if (iphdr->ip_p == IPPROTO_ICMP) {
        parsed.protocol = "ICMP";
        parsed.src_port = 0;
        parsed.dst_port = 0;
    } else {
        parsed.protocol = "OTHER";
        parsed.src_port = 0;
        parsed.dst_port = 0;
    }

    return parsed;
}

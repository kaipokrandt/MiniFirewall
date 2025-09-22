#pragma once
#include <string>
#include <cstdint>

struct ParsedPacket {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string protocol; // "TCP", "UDP", "ICMP", etc.
    size_t length;
};

ParsedPacket parse_packet(const unsigned char *packet, size_t length);

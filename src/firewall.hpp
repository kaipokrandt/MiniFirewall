#pragma once
#include "packet.hpp"
#include <string>
#include <vector>

struct FirewallRule {
    std::string src_ip;
    std::string dst_ip;
    std::string protocol; // "TCP", "UDP", "ICMP", etc.
    uint16_t src_port;   // 0 = any
    uint16_t dst_port;   // 0 = any
    bool allow;          // true = allow, false = block
};

class Firewall {
public:
    Firewall() = default;
    bool load_rules(const std::string& filepath);
    bool check_packet(const ParsedPacket& pkt) const;
private:
    std::vector<FirewallRule> rules_;
};

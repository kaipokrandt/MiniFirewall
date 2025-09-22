#include "firewall.hpp"
#include <fstream>
#include <sstream>
#include <iostream>

bool Firewall::load_rules(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open rules file: " << filepath << std::endl;
        return false;
    }

    rules_.clear();
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        FirewallRule rule{};
        std::string allow_str;
        iss >> allow_str >> rule.protocol >> rule.src_ip >> rule.dst_ip >> rule.src_port >> rule.dst_port;
        rule.allow = (allow_str == "ALLOW");
        rules_.push_back(rule);
    }
    return true;
}

bool Firewall::check_packet(const ParsedPacket& pkt) const {
    for (const auto& rule : rules_) {
        bool match = true;
        if (rule.protocol != "ANY" && rule.protocol != pkt.protocol) match = false;
        if (rule.src_ip != "ANY" && rule.src_ip != pkt.src_ip) match = false;
        if (rule.dst_ip != "ANY" && rule.dst_ip != pkt.dst_ip) match = false;
        if (rule.src_port != 0 && rule.src_port != pkt.src_port) match = false;
        if (rule.dst_port != 0 && rule.dst_port != pkt.dst_port) match = false;
        if (match) return rule.allow;
    }
    return true; // default allow
}

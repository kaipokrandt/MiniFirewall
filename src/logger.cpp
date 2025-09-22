#include "logger.hpp"
#include <iostream>
#include <ctime>

void log_packet(const ParsedPacket& pkt) {
    char timebuf[64];
    std::time_t t = std::time(nullptr);
    std::strftime(timebuf, sizeof timebuf, "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    std::cout << "[" << timebuf << "] "
              << pkt.src_ip << ":" << pkt.src_port << " -> "
              << pkt.dst_ip << ":" << pkt.dst_port << " "
              << pkt.protocol << " Length: " << pkt.length << " bytes"
              << std::endl;
}

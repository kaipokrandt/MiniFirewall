cmake_minimum_required(VERSION 3.10)
project(MiniFirewall)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS} src)
link_directories(${PCAP_LIBRARY_DIRS})

add_executable(minifw
    src/main.cpp
    src/firewall.cpp
    src/packet.cpp
    src/logger.cpp
)

target_link_libraries(minifw ${PCAP_LIBRARIES})

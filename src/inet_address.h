#ifndef TCPMANY_INET_ADDRES_H_
#define TCPMANY_INET_ADDRES_H_

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <sstream>

#include "base.h"
#include "logging.h"

namespace tcpmany {
class InetAddress {
 public:
  InetAddress() = delete;
  ~InetAddress() = default;

  InetAddress(const std::string& ip_port) {
    size_t sep_pos = ip_port.find(':');
    CHECK(sep_pos != std::string::npos);
    addr_.sin_family = AF_INET;
    std::string ip_str = ip_port.substr(0, sep_pos);
    std::string port_str = ip_port.substr(sep_pos+1, ip_port.length());
    addr_.sin_port = ::htons(std::stoi(port_str));
    CHECK(::inet_pton(AF_INET, ip_str.c_str(), &addr_.sin_addr) != 0)
        << "convert ip failed";
  }
  InetAddress(const struct sockaddr_in& addr) : addr_(addr) {}
  InetAddress(const std::string& ip, uint16 port) {
    addr_.sin_family = AF_INET;
    addr_.sin_port = ::htons(port);
    CHECK(::inet_pton(AF_INET, ip.c_str(), &addr_.sin_addr) != 0)
        << "convert ip failed";
  }
  InetAddress(uint32 ip_host, uint16 port_host) {
    addr_.sin_family = AF_INET;
    addr_.sin_port = ::htons(port_host);
    addr_.sin_addr.s_addr = ::htonl(ip_host);
  }

  std::string ToIpPort() const {
    std::ostringstream stream;
    char buf[32] = {0};
    ::inet_ntop(AF_INET, &addr_.sin_addr, buf,
        static_cast<socklen_t>(sizeof(buf)));
    uint16 port = ::ntohs(addr_.sin_port);
    stream << buf << ':' << port;
    return stream.str();
  }

  const struct sockaddr_in& SockAddr() const {
    return addr_;
  }

 private:
  struct sockaddr_in addr_;
};
}
#endif  // TCPMANY_INET_ADDRES_H_

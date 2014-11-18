#ifndef TCPMANY_PACKET_H_
#define TCPMANY_PACKET_H_

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <errno.h>
#include <ostream>
#include <string>
#include <memory>
#include <utility>

#include "base.h"
#include "logging.h"
#include "inet_address.h"

namespace tcpmany {

struct Packet;
typedef std::shared_ptr<Packet> PacketPtr;

struct Packet {
  static const uint32 MAX_SIZE = ETH_FRAME_LEN;
  static const uint16 HEADER_LEN = sizeof(struct iphdr) + sizeof(struct tcphdr);

  union {
    unsigned char raw[MAX_SIZE];
    struct {
      struct iphdr ip;
      struct tcphdr tcp;
      unsigned char data[MAX_SIZE - HEADER_LEN];
    } pkt;
  };

  Packet() {
    ::memset(raw, 0, sizeof(raw));
    pkt.ip.version = IPVERSION;
    pkt.ip.ihl = sizeof(pkt.ip) / 4;
    pkt.ip.tos = 0x04;
    pkt.ip.tot_len = ::htons(HEADER_LEN);
    pkt.ip.id = 11111;  // TODO
    pkt.ip.frag_off = 0;
    pkt.ip.ttl = IPDEFTTL;
    pkt.ip.protocol = IPPROTO_TCP;

    pkt.tcp.doff = sizeof(struct tcphdr) / 4;
    pkt.tcp.window = ::htons(4096);
    pkt.tcp.urg_ptr = 0;
  }

  bool IsTcp() const { return pkt.ip.protocol == IPPROTO_TCP; }
  void SetSyn() { pkt.tcp.syn = 1; }
  bool IsSyn() const { return pkt.tcp.syn == 1; }
  void SetAck() { pkt.tcp.ack = 1; }
  bool IsAck() const { return pkt.tcp.ack == 1; }
  void SetFin() { pkt.tcp.fin = 1; }
  bool IsFin() const { return pkt.tcp.fin == 1; }
  void SetPsh() { pkt.tcp.psh = 1; }
  bool IsPsh() const { return pkt.tcp.psh == 1; }
  void SetSeq(uint32 n) { pkt.tcp.seq = ::htonl(n); }
  uint32 GetSeq() const { return ::ntohl(pkt.tcp.seq); }
  void SetAckSeq(uint32 n) { pkt.tcp.ack_seq = ::htonl(n); }
  uint32 GetAckSeq() const { return ::ntohl(pkt.tcp.ack_seq); }

  void SetSrcAddress(const InetAddress& addr) {
    pkt.ip.saddr = addr.SockAddr().sin_addr.s_addr;
    pkt.tcp.source = addr.SockAddr().sin_port;
  }
  void SetDstAddress(const InetAddress& addr) {
    pkt.ip.daddr = addr.SockAddr().sin_addr.s_addr;
    pkt.tcp.dest = addr.SockAddr().sin_port;
  }
  void SetAddress(const InetAddress& dst, const InetAddress& src) {
    SetDstAddress(dst);
    SetSrcAddress(src);
  }
  std::string SrcIpPortString() const {
    char buf[32] = {0};
    snprintf(buf, sizeof(buf), "%s:%d",
        inet_ntoa({s_addr: pkt.ip.saddr}), ntohs(pkt.tcp.source));
    return buf;
  }
  std::string DstIpPortString() const {
    char buf[32] = {0};
    snprintf(buf, sizeof(buf), "%s:%d",
        inet_ntoa({s_addr: pkt.ip.daddr}), ntohs(pkt.tcp.dest));
    return buf;
  }
  struct sockaddr_in DstSockAddr() const {
    return {sin_family: AF_INET,
            sin_port: pkt.tcp.dest,
            sin_addr: {s_addr: pkt.ip.daddr}};
  }

  const unsigned char* Raw() const {
    return raw;
  }
  unsigned char* Buffer() {
    return raw;
  }
  const char* Data() const {
    return reinterpret_cast<const char*>(&pkt.tcp) + pkt.tcp.doff * 4;
  }
  int DataLen() const {
    return ::ntohs(pkt.ip.tot_len) - sizeof(struct iphdr) - pkt.tcp.doff * 4;
  }
  void SetData(const std::string& data) {
    CHECK(data.size() <= sizeof(pkt.data));
    ::memcpy(pkt.data, data.c_str(), data.length());
    pkt.ip.tot_len += ::htons(data.length());
  }

  size_t Size() const {
    return ::ntohs(pkt.ip.tot_len);
  }

  void ExchangeAddress(const Packet& p) {
    pkt.ip.saddr = p.pkt.ip.daddr;
    pkt.ip.daddr = p.pkt.ip.saddr;
    pkt.tcp.source = p.pkt.tcp.dest;
    pkt.tcp.dest = p.pkt.tcp.source;
  }

  static uint16 Checksum(const void* data, int len) {
    CHECK(len % 2 == 0);
    const uint16* p = static_cast<const uint16*>(data);
    int sum = 0;
    for (int i = 0; i < len; i+=2) {
      sum += *p++;
    }
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    CHECK(sum <= 0xffff);
    return ~sum;
  }

  void CalculateChecksum() {
    pkt.ip.check = 0;
    pkt.ip.check = Checksum(raw, sizeof(struct iphdr)-8);

    pkt.tcp.check = 0;
    // TODO deal with data length
    int data_len = DataLen();
    int padding_data_len = (data_len & 1) ? data_len+1 : data_len;

    struct PseudoHeader {
      uint8 allways_zero;
      uint8 protocol;
      uint16 tcp_len;
    };
    struct PseudoHeader* pseudo =
        reinterpret_cast<struct PseudoHeader*>(
            raw + HEADER_LEN + padding_data_len);
    pseudo->allways_zero = 0;
    pseudo->protocol = IPPROTO_TCP;
    pseudo->tcp_len = ::htons(sizeof(struct tcphdr) + data_len);
    pkt.tcp.check = Checksum(&pkt.ip.saddr,
                             sizeof(struct tcphdr) + 12 + padding_data_len);
  }
};

inline std::ostream& operator<<(std::ostream& os, const Packet& packet) {
  const iphdr& ip = packet.pkt.ip;
  const tcphdr& tcp = packet.pkt.tcp;
  os << "ip:{version:" << ip.version << ","
     << "ihl:" << ip.ihl << ","
     << "tos:" << (int)ip.tos << ","
     << "tot_len:" << ::ntohs(ip.tot_len) << ","
     << "id:" << ip.id << ","
     << "frag_off:" << ip.frag_off << ","
     << "ttl:" << (int)ip.ttl << ","
     << "protocol:" << (int)ip.protocol << ","
     << "check:" << ip.check << "},"
     << "saddr:" << ::inet_ntoa({s_addr: ip.saddr}) << ","
     << "daddr:" << ::inet_ntoa({s_addr: ip.daddr}) << ",tcp:{"
     << "source:" << ::ntohs(tcp.source) << ","
     << "dest:" << ::ntohs(tcp.dest) << ","
     << "seq:" << ::ntohl(tcp.seq) << ","
     << "ack_seq:" << ::ntohl(tcp.ack_seq) << ","
     << "res1:" << tcp.res1 << ","
     << "doff:" << tcp.doff << ","
     << "fin:" << tcp.fin << ","
     << "syn:" << tcp.syn << ","
     << "rst:" << tcp.rst << ","
     << "psh:" << tcp.psh << ","
     << "ack:" << tcp.ack << ","
     << "urg:" << tcp.urg << ","
     << "res2:" << tcp.res2 << ","
     << "window:" << tcp.window << ","
     << "check:" << tcp.check << ","
     << "urg_ptr:" << tcp.urg_ptr << "}";
  return os;
}

inline PacketPtr SynPacket(uint32 seq,
                           const InetAddress& dst,
                           const InetAddress& src) {
  auto packet = std::make_shared<Packet>();
  packet->SetAddress(dst, src);
  packet->SetSyn();
  packet->SetSeq(seq);
  return packet;
}

inline PacketPtr FinPacket(uint32 seq,
                           uint32 ack_seq,
                           const InetAddress& dst,
                           const InetAddress& src) {
  auto packet = std::make_shared<Packet>();
  packet->SetAddress(dst, src);
  packet->SetFin();
  packet->SetSeq(seq);
  packet->SetAck();
  packet->SetAckSeq(ack_seq);
  return packet;
}

inline PacketPtr AckPacket(uint32 seq, const Packet& rp) {
  auto sp = std::make_shared<Packet>();
  sp->ExchangeAddress(rp);
  sp->SetAck();
  int data_len = rp.DataLen();
  if (data_len > 0) {
    sp->SetAckSeq(rp.GetSeq() + data_len);
  } else {
    sp->SetAckSeq(rp.GetSeq()+1);
  }
  sp->SetSeq(seq);
  return sp;
}

inline PacketPtr FinAckPacket(uint32 seq, const Packet& rp) {
  auto sp = std::make_shared<Packet>();
  sp->ExchangeAddress(rp);
  sp->SetFin();
  sp->SetAck();
  sp->SetAckSeq(rp.GetSeq() + 1);
  sp->SetSeq(seq);
  return sp;
}

inline PacketPtr DataPacket(uint32 seq,
                            uint32 ack_seq,
                            const InetAddress& dst,
                            const InetAddress& src,
                            const std::string& message) {
  auto sp = std::make_shared<Packet>();
  sp->SetAddress(dst, src);
  sp->SetPsh();
  sp->SetSeq(seq);
  sp->SetAck();
  sp->SetAckSeq(ack_seq);
  sp->SetData(message);
  return sp;
}

}
#endif  // TCPMANY_PACKET_H_

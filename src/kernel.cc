#include "kernel.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <linux/if_ether.h>
#include <functional>
#include <string>

#include "packet.h"
#include "connection.h"

using std::string;

namespace tcpmany {

const static char LAST_PACKET_DATA[] = "lastpacket";
static PacketPtr LastPacket() {
  auto packet = std::make_shared<Packet>();
  ::memcpy(packet->Buffer(), LAST_PACKET_DATA, sizeof(LAST_PACKET_DATA));
  return packet;
}

static bool IsLastPacket(PacketPtr& packet) {
  return !::memcmp(packet->Raw(), LAST_PACKET_DATA, sizeof(LAST_PACKET_DATA));
}

Kernel::Kernel()
    : sockfd_(-1),
      receive_stop_state_(SS_STOPED),
      stoped_(false) {
  sockfd_ = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  CHECK(sockfd_ >= 0) << "socket error: " << strerror(errno);
  int flag = 1;
  CHECK(setsockopt(sockfd_, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) >= 0)
      << "setsockopt error: " << strerror(errno);
}

Kernel::~Kernel() {
  DoStop();
  ::fflush(stderr);
}

void Kernel::DoStop() {
  if (!stoped_) {
    stoped_ = true;
    for (auto& iter : connections_) {
      iter.second->SetClosedCallback([](Connection& conn) {
          LOG(INFO) << "Connection Closed: " << conn.GetSrcAddress().ToIpPort();
          Kernel::Remove(conn);
      });
      iter.second->Close(); 
    }
    while (!connections_.empty()) {
      ::sleep(1);
      LOG(INFO) << "waiting for all connection closing";
    }
    LOG(INFO) << "all connection closed";
    receive_stop_state_ = SS_STOPING;
    if (receive_thread_.joinable()) {
      receive_thread_.join();
    }
    packets_.Push(LastPacket());
    if (send_thread_.joinable()) {
      send_thread_.join();
    }
    ::close(sockfd_);
  }
}

void Kernel::ReceiveThread() {
  receive_stop_state_ = SS_RUNNING;
  while (receive_stop_state_ == SS_RUNNING) {
    auto packet = std::make_shared<Packet>();
    int len = recvfrom(sockfd_,
                       packet->Buffer(),
                       Packet::MAX_SIZE,
                       0,
                       NULL,
                       NULL);
    if (len < 0) {
      LOG(ERROR) << "recvfrom error: " << strerror(errno);
      continue;
    }
    if (len < Packet::HEADER_LEN) {
      LOG(INFO) << "recvfrom length(" << len << ") is too small";
      continue;
    }
    VLOG(4) << "receive packet: " << *packet;
    if (!packet->IsTcp()) {
      LOG(INFO) << "invalid tcp packet";
      continue;
    }
    string ip_port = packet->DstIpPortString();
    Connection* conn = FindConnection(ip_port);
    if (conn == nullptr) {
      VLOG(3) << "no connection match the packet";
      continue;
    } else {
      conn->ProcessPacket(*packet);
    }
  }
  receive_stop_state_ = SS_STOPED;
  LOG(INFO) << "receive thread exited";
}

void Kernel::SendThread() {
  while (true) {
    PacketPtr packet;
    packets_.Pop(packet);
    if (IsLastPacket(packet)) {
      break;
    }
    CHECK(sockfd_ != -1);
    struct sockaddr_in dst_addr = packet->DstSockAddr();
    int ret = sendto(sockfd_,
                     packet->Raw(),
                     packet->Size(),
                     0,
                     (struct sockaddr*)&dst_addr,
                     sizeof(struct sockaddr));
    if (ret == -1) {
      LOG(ERROR) << "sendto error: " << ::strerror(errno);
    }
  }
  LOG(INFO) << "send thread exited";
}

void Kernel::DoSend(std::shared_ptr<Packet> packet) {
  packet->CalculateChecksum();
  packets_.Push(packet);
}

void Kernel::DoStart() {
  CHECK(!send_thread_.joinable());
  CHECK(!receive_thread_.joinable());
  send_thread_ = std::thread(&Kernel::SendThread, this);
  receive_thread_ = std::thread(&Kernel::ReceiveThread, this);
}

Connection* Kernel::DoNewConnection(const InetAddress& dst_addr,
                                    const InetAddress& src_addr) {
  std::string ip_port = src_addr.ToIpPort();
  // TODO consider throw an exception instead
  CHECK(connections_[ip_port] == nullptr)
      << "the src_addr is already in use: " << ip_port;
  Connection* conn = new Connection(dst_addr, src_addr);
  connections_[ip_port] = conn;
  return conn;
}

Connection* Kernel::FindConnection(const std::string& ip_port) {
  auto iter = connections_.find(ip_port);
  if (iter == connections_.end()) {
    return nullptr;
  }
  return iter->second;
}

void Kernel::DoRemove(Connection& conn) {
  CHECK(conn.IsClosed());
  std::string address = conn.GetSrcAddress().ToIpPort();
  connections_.erase(address);
  delete &conn;
}

}

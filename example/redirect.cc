#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <pcap.h>
#include <iostream>
#include <memory>
#include "logging.h"
#include "packet.h"

using std::cerr;
using std::endl;
using std::make_shared;

uint32 g_client_ip_net;
uint16 g_server_port;
int g_sockfd;

void ProcessPacket(u_char *args,
                   const struct pcap_pkthdr *header,
                   const u_char *packet_data) {
  static const int SIZE_ETHERNET = 14;
  tcpmany::Packet packet;
  ::memcpy(packet.Buffer(),
           packet_data+SIZE_ETHERNET,
           tcpmany::Packet::MAX_SIZE);
  if (packet.SrcPort() == g_server_port &&
      packet.DstIpNet() != g_client_ip_net) {
    uint32 dst_ip_net = packet.DstIpNet();
    packet.SetDstIpNet(g_client_ip_net);
    packet.SetSrcIpNet(dst_ip_net);
    packet.SetSrcPortNet(packet.DstPortNet());
    packet.CalculateChecksum();
    VLOG(3) << "redirect pakcet: " << packet;

    struct sockaddr_in dst_addr = packet.DstSockAddr();
    CHECK(g_sockfd > 0);
    int ret = sendto(g_sockfd,
                     packet.Buffer(),
                     packet.Size(),
                     0,
                     (struct sockaddr*)&dst_addr,
                     sizeof(struct sockaddr));
    if (ret == -1) {
      LOG(ERROR) << "sendto error: " << ::strerror(errno);
    }
  }
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    cerr << "usage: " << argv[0]
         << " <client_ip> <server_port> <interface>" << endl;
    return -1;
  }

  struct sockaddr_in addr;
  CHECK(::inet_pton(AF_INET, argv[1], &addr.sin_addr) != 0);
  g_client_ip_net = addr.sin_addr.s_addr;
  g_server_port = atoi(argv[2]);
  const char* interface = argv[3];

  g_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  CHECK(g_sockfd >= 0) << "socket error: " << strerror(errno);
  int flag = 1;
  CHECK(setsockopt(g_sockfd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) >= 0)
      << "setsockopt error: " << strerror(errno);

  char err[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask;
  bpf_u_int32 net;
  CHECK(pcap_lookupnet(interface, &net, &mask, err) == 0)
      << "get interface info failed: " << err;

  const int SNAP_LEN = 1518;
  const int PROMISC_MODe = 1;
  const int TIMEOUT_MS = 1000;
  pcap_t* handle = pcap_open_live(interface,
                                  SNAP_LEN,
                                  PROMISC_MODe,
                                  TIMEOUT_MS,
                                  err);
  CHECK(handle != NULL) << "open interface failed: " << err;
  CHECK(pcap_datalink(handle) == DLT_EN10MB) << "not an ethernet interface";

  const char filter_exp[] = "tcp port 5223";
  struct bpf_program fp;
  CHECK(pcap_compile(handle, &fp, filter_exp, 0, net) == 0)
      << "compile filter expression failed: " << pcap_geterr(handle);
  CHECK(pcap_setfilter(handle, &fp) == 0)
      << "set filter failed: " << pcap_geterr(handle);

  pcap_loop(handle, -1, ProcessPacket, NULL);

  LOG(INFO) << "redirect loop exited";
  ::close(g_sockfd);
  pcap_freecode(&fp);
  pcap_close(handle);
}

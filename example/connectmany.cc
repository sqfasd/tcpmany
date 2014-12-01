#include <string>
#include <iostream>
#include <functional>
#include "connection.h"
#include "kernel.h"

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;

using tcpmany::Kernel;
using tcpmany::Connection;
using tcpmany::InetAddress;

void OnConnected(int id, Connection& conn) {
  cout << "OnConnected id=" << id << endl;
  char buf[1024] = {0};
  sprintf(buf,
    "GET /sub?uid=%d HTTP/1.1\r\n"
    "User-Agent: tcpmany/0.1.0\r\n"
    "Host: localhost:9000\r\n"
    "Accept: */*\r\n"
    "\r\n",
    id);
  conn.Send(buf);
}

void OnMessage(int id, Connection& conn, const char* msg, int msg_len) {
  cout << "OnMessage id=" << id << endl << string(msg, msg_len) << endl;
}

int main(int argc, char* argv[]) {
  if (argc != 5) {
    cerr << "usage: " << argv[0] << " <ip> <port> <count> <local_ip>" << endl;
    return -1;
  }
  Kernel::Start();

  const char* SERVER_IP = argv[1];
  const uint16 SERVER_PORT = atoi(argv[2]);
  const int COUNT = atoi(argv[3]);
  const uint16 LOCAL_PORT = 13579;

  InetAddress server_addr(SERVER_IP, SERVER_PORT);

  uint32 ip = ::ntohl(::inet_addr(argv[4]));
  for (int i = 0; i < COUNT; ++i) {
    InetAddress client_addr(ip++, LOCAL_PORT);
    Connection* conn = Kernel::NewConnection(server_addr, client_addr);
    conn->SetConnectedCallback(std::bind(&OnConnected, i, _1));
    conn->SetMessageCallback(std::bind(&OnMessage, i, _1, _2, _3));
    conn->Connect();
  }
  cout << "press any key to finish" << endl;
  getchar();
  Kernel::Stop();
}

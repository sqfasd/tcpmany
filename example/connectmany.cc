#include <string>
#include <iostream>
#include "connection.h"
#include "kernel.h"

using std::cout;
using std::cerr;
using std::endl;
using std::string;

using tcpmany::Kernel;
using tcpmany::Connection;
using tcpmany::InetAddress;

void OnConnected(Connection& conn) {
  cout << "OnConnected" << endl;
  conn.Send("hello world!");
}

void OnMessage(Connection& conn, const char* msg, int msg_len) {
  cout << "OnMessage: " << string(msg, msg_len) << endl;
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    cerr << "usage: " << argv[0] << " <ip> <port> <count>" << endl;
    return -1;
  }
  Kernel::Start();

  const char* SERVER_IP = argv[1];
  const uint16 SERVER_PORT = atoi(argv[2]);
  const int COUNT = atoi(argv[3]);
  const uint16 LOCAL_PORT = 13579;

  InetAddress server_addr(SERVER_IP, SERVER_PORT);

  uint32 ip = inet_addr("127.0.0.1");
  for (int i = 0; i < COUNT; ++i) {
    InetAddress client_addr(ip++, ::htons(LOCAL_PORT));
    Connection* conn = Kernel::NewConnection(server_addr, client_addr);
    conn->SetConnectedCallback(&OnConnected);
    conn->SetMessageCallback(&OnMessage);
    conn->Connect();
  }
  cout << "press any key to finish" << endl;
  getchar();
  Kernel::Stop();
}

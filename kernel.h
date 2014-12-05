#ifndef TCPMANY_KERNEL_H_
#define TCPMANY_KERNEL_H_

#include <string>
#include <unordered_map>
#include <thread>
#include <memory>
#include <atomic>
#include <mutex>

#include "base/basictypes.h"
#include "base/noncopyable.h"
#include "base/singleton.h"
#include "base/blocking_queue.h"
#include "inet_address.h"

namespace tcpmany {

struct Packet;
class Connection;
typedef std::unordered_map<std::string, std::shared_ptr<Connection>> ConnectionMap;

class Kernel : public NonCopyable {
 public:
  static void Start() {
    Singleton<Kernel>::Instance().DoStart();
  }
  static void Stop() {
    Singleton<Kernel>::Instance().DoStop();
  }

  // Kernel will take ownership of the connection
  static std::shared_ptr<Connection> NewConnection(const InetAddress& dst_addr,
                                   const InetAddress& src_addr) {
    return Singleton<Kernel>::Instance().DoNewConnection(dst_addr, src_addr);
  }
  static void Send(std::shared_ptr<Packet> packet) {
    Singleton<Kernel>::Instance().DoSend(packet);
  }
  static void Release(std::shared_ptr<Connection> conn) {
    Singleton<Kernel>::Instance().DoRelease(conn);
  }

 private:
  Kernel();
  ~Kernel();
  void DoStart();
  void DoStop();
  std::shared_ptr<Connection> DoNewConnection(const InetAddress& dst_addr,
                              const InetAddress& src_addr);
  void DoSend(std::shared_ptr<Packet> packet);

  void ReceiveThread();
  void SendThread();
  Connection* FindConnection(const std::string& address);
  void InsertConnection(const std::string& addr, std::shared_ptr<Connection> conn);

  // must close it before remove
  void DoRelease(std::shared_ptr<Connection> conn);

  ConnectionMap connections_;
  std::mutex conn_mutex_;

  std::thread receive_thread_;
  std::thread send_thread_;
  int sockfd_;
  BlockingQueue<std::shared_ptr<Packet>> packets_;

  enum StopStatus {
    SS_STOPED,
    SS_RUNNING,
    SS_STOPING,
  };
  StopStatus receive_stop_state_;
  std::atomic<bool> stoped_;

  friend class Singleton<Kernel>;
  friend class Connection;
};

}
#endif  // TCPMANY_KERNEL_H_

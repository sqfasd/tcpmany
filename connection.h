#ifndef TCPMANY_CONNECTION_H_
#define TCPMANY_CONNECTION_H_

#include <string>
#include <functional>
#include <atomic>
#include <memory>

#include "base/basictypes.h"
#include "base/noncopyable.h"
#include "packet.h"

namespace tcpmany {

class Kernel;
class Connection;
typedef std::shared_ptr<Connection> ConnectionPtr;
typedef std::function<void (ConnectionPtr)> ConnectedCallback;
typedef std::function<void (ConnectionPtr, const char*, int)> MessageCallback;
typedef std::function<void (ConnectionPtr)> ClosedCallback;

class Connection : NonCopyable,
                   public std::enable_shared_from_this<Connection> {
 public:
  ~Connection();

  void SetConnectedCallback(const ConnectedCallback& cb) {
    connected_callback_ = cb;
  }
  void SetMessageCallback(const MessageCallback& cb) {
    message_callback_ = cb;
  }
  void SetClosedCallback(const ClosedCallback& cb) {
    closed_callback_ = cb;
  }
  // TODO process the events error/close/timeout
  // void OnError();
  // void OnClosed();
  // void OnTimeout(int time_out, const TimeoutCallback& cb);
  const InetAddress& GetSrcAddress() const {
    return src_addr_;
  }

  const InetAddress& GetDstAddress() const {
    return dst_addr_;
  }

  bool IsClosed() const {
    return state_ == CS_CLOSED;
  }

  void Connect();
  void Close();
  void Send(const std::string& message);

 private:
  Connection(const InetAddress& dst_addr, const InetAddress& src_addr);
  void ProcessPacket(const Packet& packet);
  void ProcessMessage(const Packet& packet);

  ConnectedCallback connected_callback_;
  MessageCallback message_callback_;
  ClosedCallback closed_callback_;
  const InetAddress dst_addr_;
  const InetAddress src_addr_;

  enum ConnState {
    CS_CLOSED,
    CS_SYN_SENT,
    CS_ESTABLISHED,
    CS_FIN_WAIT_1,
    CS_FIN_WAIT_2,
    CS_CLOSING,
    CS_TIME_WAIT,
  } state_;

  std::atomic<uint32> seq_;
  std::atomic<uint32> ack_seq_;

  friend class Kernel;
};

}

#endif  // TCPMANY_CONNECTION_H_

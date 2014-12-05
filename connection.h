#ifndef TCPMANY_CONNECTION_H_
#define TCPMANY_CONNECTION_H_

#include <string>
#include <functional>
#include <atomic>

#include "base.h"
#include "noncopyable.h"
#include "packet.h"

namespace tcpmany {

class Kernel;
class Connection;
typedef std::function<void (Connection&)> ConnectedCallback;
typedef std::function<void (Connection&, const char*, int)> MessageCallback;
typedef std::function<void (Connection&)> ClosedCallback;

class Connection : public NonCopyable {
 public:
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
  ~Connection();
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

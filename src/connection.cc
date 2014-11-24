#include "connection.h"

#include <time.h>
#include <memory>
#include "kernel.h"
#include "logging.h"

namespace tcpmany {

void DefaultConnectedCallback(Connection&) {
}

void DefaultMessageCallback(Connection&, const char*, int) {
}

void DefaultClosedCallback(Connection&) {
}

Connection::Connection(const InetAddress& dst_addr,
                       const InetAddress& src_addr)
    : connected_callback_(DefaultConnectedCallback),
      message_callback_(DefaultMessageCallback),
      closed_callback_(DefaultClosedCallback),
      dst_addr_(dst_addr),
      src_addr_(src_addr),
      state_(CS_CLOSED),
      seq_(::time(0) + ::clock()) {
}

Connection::~Connection() {
}

void Connection::Connect() {
  Kernel::Send(SynPacket(seq_++, dst_addr_, src_addr_));
  state_ = CS_SYN_SENT;
}

void Connection::Close() {
  Kernel::Send(FinPacket(seq_++, ack_seq_, dst_addr_, src_addr_));
  state_ = CS_FIN_WAIT_1;
}

void Connection::Send(const std::string& message) {
  Kernel::Send(DataPacket(seq_.fetch_add(message.length()),
                          ack_seq_,
                          dst_addr_,
                          src_addr_,
                          message));
}

void Connection::ProcessPacket(const Packet& packet) {
  int data_len = packet.DataLen();
  VLOG(3) << "data(" << data_len << "):"
          << std::string(packet.Data(), data_len);
  if (data_len > 0) {
    ack_seq_.store(packet.GetSeq() + data_len);
  } else {
    ack_seq_.store(packet.GetSeq() + 1);
  }
  switch (state_) {
    case CS_CLOSED:
      break;
    case CS_SYN_SENT:
      if (packet.IsSyn() && packet.IsAck()) {
        Kernel::Send(AckPacket(seq_, packet, dst_addr_, src_addr_));
        state_ = CS_ESTABLISHED;
        connected_callback_(*this);
      }
      //TODO if receive packet send by self
      break;
    case CS_ESTABLISHED:
      ProcessMessage(packet);
      break;
    case CS_FIN_WAIT_1:
      if (packet.IsAck()) {
        state_ = CS_FIN_WAIT_2;
      } else if (packet.IsFin()) {
        Kernel::Send(AckPacket(seq_, packet, dst_addr_, src_addr_));
        state_ = CS_CLOSING;
      }
      break;
    case CS_FIN_WAIT_2:
      if (packet.IsFin()) {
        Kernel::Send(AckPacket(seq_, packet, dst_addr_, src_addr_));
        state_ = CS_CLOSED; // CS_TIME_WAIT;
        closed_callback_(*this);
      }
      break;
    case CS_CLOSING:
      if (packet.IsAck()) {
        state_ = CS_CLOSED; // CS_TIME_WAIT;
        closed_callback_(*this);
      }
      break;
    case CS_TIME_WAIT:
      break;
  }
}

void Connection::ProcessMessage(const Packet& packet) {
  // TODO process message packet
  int data_len = packet.DataLen();
  if (data_len > 0) {
    Kernel::Send(AckPacket(seq_, packet, dst_addr_, src_addr_));
    message_callback_(*this, packet.Data(), data_len);
  } else if (packet.IsAck()) {
    // TODO clear the resend timer
    LOG(WARNING) << "[FIXME] receive ack";
  } else if (packet.IsFin()) {
    Kernel::Send(FinAckPacket(seq_, packet, dst_addr_, src_addr_));
    state_ = CS_CLOSING;
  }
}

}  // namespace tcpmany

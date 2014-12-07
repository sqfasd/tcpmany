#ifndef TCPMANY_TIMER_H_
#define TCPMANY_TIMER_H_

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <strings.h>
#include <errno.h>
#include <atomic>
#include <functional>
#include <set>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <algorithm> 
#include "base/basictypes.h"
#include "base/noncopyable.h"
#include "base/logging.h"
#include "timestamp.h"

namespace tcpmany {

typedef int TimerId;
typedef std::function<void()> TimerCallback;

class Timer : public NonCopyable {
 public:
  ~Timer() {}
  void Run() const {callback_();}
  Timestamp Expiration() const {return expiration_;}
  TimerId Id() const {return id_;}

 private:
  Timer(Timestamp when, const TimerCallback& cb)
      : id_(s_timer_sequence_++),
        expiration_(when),
        callback_(cb) {
  }

  TimerId id_;
  Timestamp expiration_;
  std::function<void()> callback_; 

  static std::atomic<int64> s_timer_sequence_;

  friend class TimerManager;
};

class TimerManager : public NonCopyable {
 public:
  TimerManager() : stoped_(false) {
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, pipe_) == 0);

    int flags;
    flags = fcntl(pipe_[1], F_GETFL);
    flags |= O_NONBLOCK;
    CHECK(fcntl(pipe_[1], F_SETFL, flags) != -1);
  }

  ~TimerManager() {
    ::close(pipe_[0]);
    ::close(pipe_[1]);
    for (Timer* timer : timers_) {
      delete timer;
    }
  }

  void Stop() {
    stoped_ = true;
  }

  TimerId AddTimer(Timestamp when, const TimerCallback& cb) {
    std::unique_lock<std::mutex> lock(mutex_);
    bool has_early_timer = false;
    if (timers_.empty() || when < (*timers_.begin())->Expiration()) {
      has_early_timer = true;
    }

    Timer* timer = new Timer(when, cb);
    timers_.insert(timer);
    id_mapping_[timer->Id()] = timer;

    if (has_early_timer) {
      Notify();
    }
    return timer->Id();
  }

  void CancelTimer(TimerId id) {
    std::unique_lock<std::mutex> lock(mutex_);
    auto it = id_mapping_.find(id);
    if (it != id_mapping_.end()) {
      timers_.erase(it->second);
    }
  }

  void RunExpired() {
    Wait();
    if (stoped_) {
      return;
    }
    std::vector<Timer*> expired;
    GetExpired(expired);
    for (Timer* timer : expired) {
      timer->Run();
      delete timer;
    }
  }

 private:
  void GetExpired(std::vector<Timer*>& expired) {
    std::unique_lock<std::mutex> lock(mutex_);
    Timer now(Now(), [](){});
    auto end = timers_.lower_bound(&now);
    std::copy(timers_.begin(), end, std::back_inserter(expired));
    timers_.erase(timers_.begin(), end);
  }

  void Notify() {
    char buf[1] = {1};
    ::send(pipe_[0], buf, 1, 0);
  }

  void Wait() {
    while (true) {
      Timestamp time_diff = TimeDiffEarliest();
      if (time_diff > ONE_MILLI_SECOND) {
        struct pollfd pfds[1];
        pfds[0].fd = pipe_[1];
        pfds[0].events = POLLIN; 
        int ret = ::poll(pfds, 1, time_diff / ONE_MILLI_SECOND);
        if (ret == 0) {
          VLOG(5) << "poll time out";
        } else if (ret > 0) {
          VLOG(5) << "receive the notification, check again";
          char buf[1] = {0};
          while (read(pipe_[1], buf, 1) > 0) {
          }
        } else {
          LOG(ERROR) << "poll error: " << ::strerror(errno);
        }
        if (stoped_) {
          if (!timers_.empty()) {
            LOG(WARNING) << "stoped with " << timers_.size()
                         << " timers not run";
          }
          break;
        } else {
          continue;
        }
      } else {
        break;
      }
    }
  }

  Timestamp TimeDiffEarliest() {
    std::unique_lock<std::mutex> lock(mutex_);
    return timers_.empty() ? ONE_SECOND
                           : (*timers_.begin())->Expiration() - Now();
  }

  struct CompareTimerPtr {
    bool operator()(const Timer* left, const Timer* right) const {
      return left->Expiration() < right->Expiration();
    }
  };
  std::set<Timer*, CompareTimerPtr> timers_;
  std::unordered_map<TimerId, Timer*> id_mapping_;
  std::mutex mutex_;
  int pipe_[2];
  std::atomic<bool> stoped_;
};

}  // namespace tcpmany
#endif  // TCPMANY_TIMER_H_

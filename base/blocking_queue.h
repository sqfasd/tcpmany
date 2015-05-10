#ifndef TCPMANY_BLOCKING_QUEUE_H_
#define TCPMANY_BLOCKING_QUEUE_H_

#include <queue>
#include <mutex>
#include <condition_variable>

#include "noncopyable.h"

namespace tcpmany {

template<class T>
class BlockingQueue : public NonCopyable {
 public:
  BlockingQueue() = default;
  virtual ~BlockingQueue() {}

  virtual void Push(const T& data) {
    std::unique_lock<std::mutex> lock(mutex_);
    queue_.push(data);
    condition_.notify_one();
  }

  virtual void Pop(T& data) {
    std::unique_lock<std::mutex> lock(mutex_);
    while (queue_.empty()) {
      condition_.wait(lock);
    }
    data = queue_.front();
    queue_.pop();
  }

  bool TryPop(T& data) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (queue_.empty()) {
      return false;
    }
    data = queue_.front();
    queue_.pop();
    return true;
  }

  T const& Front() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return queue_.front();
  }

  bool Empty() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return queue_.empty();
  }

  size_t Size() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return queue_.size();
  }

 protected:
  std::queue<T> queue_;
  mutable std::mutex mutex_;
  std::condition_variable condition_;
};

template<typename T>
class BoundedBlockingQueue : public BlockingQueue<T> {
 public:
  explicit BoundedBlockingQueue(size_t max_count) : max_count_(max_count) {}
  virtual ~BoundedBlockingQueue() {}

  virtual void Push(const T& data) {
    std::unique_lock<std::mutex> lock(this->mutex_);
    while (this->queue_.size() >= max_count_) {
      this->condition_full_.wait(lock);
    }
    this->queue_.push(data);
    this->condition_.notify_one();
  }

  virtual void Pop(T& data) {
    std::unique_lock<std::mutex> lock(this->mutex_);

    while (this->queue_.empty()) {
      this->condition_.wait(lock);
    }
    data = this->queue_.front();
    this->queue_.pop();
    condition_full_.notify_one();
  }

  bool Full() const {
    std::unique_lock<std::mutex> lock(this->mutex_);
    return this->queue_.size() >= max_count_;
  }

 private:
  std::condition_variable condition_full_;
  const size_t max_count_;
};

}

#endif  // TCPMANY_BLOCKING_QUEUE_H_

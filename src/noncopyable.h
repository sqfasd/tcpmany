#ifndef TCPMANY_NONCOPYABLE_H_
#define TCPMANY_NONCOPYABLE_H_

class NonCopyable {
 public:
  NonCopyable& operator=(const NonCopyable&) = delete;
  NonCopyable(const NonCopyable&) = delete;

 protected:
  NonCopyable() = default;
  ~NonCopyable() = default;
};

#endif  // TCPMANY_NONCOPYABLE_H_

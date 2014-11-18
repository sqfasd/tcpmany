#ifndef TCPMANY_LOGGING_H_
#define TCPMANY_LOGGING_H_

#include <time.h>
#include <stdio.h>
#include <sstream>
#include <thread>

#define LOG_LEVEL tcpmany::LOG_INFO
#define LOG_VERBOSE_LEVEL 3

#define LOG(severity) \
  if (LOG_LEVEL <= tcpmany::LOG_##severity) \
    tcpmany::SimpleLogger(__FILE__, __LINE__, #severity, \
        tcpmany::LOG_##severity).Stream()

#define VLOG(v) \
  if (LOG_VERBOSE_LEVEL >= v) LOG(INFO)

#define CHECK(condition) \
  if (!(condition)) \
    LOG(FATAL) << "check condition [" << #condition << "] failed: "

namespace tcpmany {

const int LOG_INFO = 0;
const int LOG_WARNING = 1;
const int LOG_ERROR = 2;
const int LOG_ERROR_REPORT = 3;
const int LOG_FATAL = 4;

class SimpleLogger {
 public:
  SimpleLogger(const char* file, int line, const char* level_str, int level)
      : level_(level) {
    time_t t = ::time(nullptr);
    struct tm* tm = ::localtime(&t);
    char time_buf[20] = {0};
    snprintf(time_buf, sizeof(time_buf), "%d%02d%02d:%02d%02d%02d",
        1900 + tm->tm_year,
        tm->tm_mon,
        tm->tm_mday,
        tm->tm_hour,
        tm->tm_min,
        tm->tm_sec);
    stream_ << std::this_thread::get_id() << ':'
            << time_buf << ':'
            << level_str << ':'
            << file << ':'
            << line << "| ";
  }
  ~SimpleLogger() {
    stream_ << '\n';
    ::fwrite(stream_.str().c_str(), 1, stream_.str().length(), stderr);
    if (level_ == LOG_FATAL) {
      ::fflush(stderr);
      ::abort();
    }
  }
  std::ostream& Stream() { return stream_; }

 private:
  std::ostringstream stream_;
  int level_;
};
}
#endif  // TCPMANY_LOGGING_H_

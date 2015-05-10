#ifndef TCPMANY_TIMESTAMP_H_
#define TCPMANY_TIMESTAMP_H_

#include <sys/time.h>
#include "base/basictypes.h"

namespace tcpmany {

typedef int64 Timestamp;
static const int64 ONE_SECOND = 1000 * 1000;
static const int ONE_MILLI_SECOND = 1000;

inline Timestamp Now() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return static_cast<int64>(tv.tv_sec) * ONE_SECOND + tv.tv_usec;
}

}  // namespace tcpmany

#endif  // TCPMANY_TIMESTAMP_H_

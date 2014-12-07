#include "timer.h"

namespace tcpmany {

std::atomic<int64> Timer::s_timer_sequence_(1);

}

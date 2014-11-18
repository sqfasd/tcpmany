#include "src/logging.h"

int main() {
  LOG(INFO) << "this is a info";
  LOG(ERROR) << "this is a error";
  LOG(WARNING) << "this is a warning";
  VLOG(1) << "verbose 1";
  VLOG(2) << "verbose 2";
  VLOG(3) << "verbose 3";
  VLOG(4) << "verbose 4";
  VLOG(5) << "verbose 5";

  CHECK(true);
  CHECK(1 + 1 == 2) << "not happend";
  CHECK(1 + 1 > 2) << "because I want to die";
}

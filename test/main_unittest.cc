#include <stdio.h>
#include <iostream>
#include "base/logging.h"
#include "tcpmany.h"

using namespace std;
using namespace tcpmany;

void TestTimer() {
  cout << "TestTimer" << endl;
  Kernel::Start();
  int* x = new int(0);
  Kernel::AddTimer(Now() + ONE_SECOND*3, [=]() {
      cout << "3 second" << endl;
      CHECK(*x == 2);
      delete x;
      cout << "TestTimer success" << endl;
    });
  Kernel::AddTimer(Now() + ONE_SECOND, [=]() {
      CHECK(*x == 0);
      *x = 1;
      cout << "1 second" << endl;
    });
  Kernel::AddTimer(Now() + ONE_SECOND*2, [=]() {
      CHECK(*x == 1);
      *x = 2;
      cout << "2 second" << endl;
    });
}

int main(int argc, char* argv[]) {
  TestTimer();
  cout << "press any key to continue" << endl;
  getchar();
  Kernel::Stop();
}

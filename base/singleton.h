#ifndef SINGLETON_H_
#define SINGLETON_H_

#include <pthread.h>
#include <stdlib.h>
#include "noncopyable.h"

namespace tcpmany {

template <class T>
class Singleton : public NonCopyable {
 public:
  static T& Instance() {
    pthread_once(&ponce_,  &Singleton::Init);
    return *instance_;
  }

  static void Init() {
    instance_ = new T();
    ::atexit(Destroy);
  }

  static void Destroy() {
    delete instance_;
  }

 private:
  Singleton();
  ~Singleton();
  static T* instance_;
  static pthread_once_t ponce_;
};

template<typename T>
pthread_once_t Singleton<T>::ponce_ = PTHREAD_ONCE_INIT;

template<typename T>
T* Singleton<T>::instance_ = NULL;

}
#endif

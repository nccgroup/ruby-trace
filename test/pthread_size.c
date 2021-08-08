#include <pthread.h>
#include <signal.h>
#include <stdio.h>

int main() {
  printf("sizeof(pthread_mutex_t): %d\n", sizeof(pthread_mutex_t));
  printf("sizeof(pthread_cond_t): %d\n", sizeof(pthread_cond_t));
  printf("NSIG: %u\n", NSIG);
  return 0;
}

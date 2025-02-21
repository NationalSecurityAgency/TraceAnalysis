#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define THREADCOUNT 3

typedef struct threadinfo {
  int tid;
  char *data;
} threadinfo_t;

void *thread_main(void *a) {
  int tid = ((threadinfo_t *)a)->tid;
  char *data = ((threadinfo_t *)a)->data;
  for (int i = 0; i < 100; i++) {
    *((int *)data) = *((int *)data) + 1;
  }
  ((int *)data)[tid + 1] = 1;
  
  printf("Hello World from %d\n", tid);

  return NULL;
}

int main(void) {
  char *data = (char *)malloc(100);
  pthread_t threads[THREADCOUNT];
  threadinfo_t args[THREADCOUNT];
  int rc;

  for (int i = 0; i < THREADCOUNT; ++i) {
    args[i].tid = i;
    args[i].data = data;
    pthread_create(&threads[i], NULL, thread_main, (void *)&args[i]);
  }

  for (int i = 0; i < THREADCOUNT; ++i) {
    pthread_join(threads[i], NULL);
  }
  
  printf("%d\n", ((int *)data)[0]);
}

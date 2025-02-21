#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct {
  unsigned int id;
  char *name;
  unsigned long hash;
} user_t;

typedef struct {
  user_t *user;
  double score;
} session_t;

typedef struct {
  char type;
  char id;
  char name[15];
  char pw[15];
} init_packet_t;

typedef struct {
  char type;
  char sz;
  char data[30];
} data_packet_t;

double score(char* data, unsigned int sz) {
  double ans = 0.0;
  if(sz > 30) sz = 30;
  for(int i = 0; i < sz; i++) {
    ans += (double)((i % 2 == 0 ? 1 : -1)*data[i])*((double)(1/((double)i+10.0)));
  }
  return ans;
}

unsigned long hash(char* data) {
  unsigned long ans = 0;
  for(int i = 0; i < 15; i++) {
    if(data[i] == 0) break;
    ans += (unsigned long)(i*i*data[i]);
  }
  return ans;
}

session_t *process(char *packet, session_t *current_session) {
  if(packet[0] == 1) {
    init_packet_t *init = (init_packet_t*)packet;
    if(current_session != NULL) {
      if(init->id == current_session->user->id) {
        // user is already in; reset score
        current_session->score = 0.0;
        return current_session;
      }
      // replacing the current user
      free(current_session->user->name);
      free(current_session->user);
      free(current_session);
    }
    current_session = (session_t *)malloc(sizeof(session_t));
    user_t *user = (user_t *)malloc(sizeof(user_t));
    user->id = init->id;
    user->name = (char*)malloc(15);
    for(int i = 0; i < 15; i++) {
      if(init->name[i] == 0) break;
      user->name[i] = init->name[i];
    }
    user->hash = hash(init->pw);
    current_session->user = user;
    current_session->score = 0.0;
  } else if(packet[0] == 2 && current_session != NULL) {
    data_packet_t *p = (data_packet_t *)packet;
    current_session->score += score(p->data, p->sz);
  } else if(packet[0] == 3) {
    if(current_session != NULL) {
      free(current_session->user->name);
      free(current_session->user);
      free(current_session);
    }
    return NULL;
  }
  return current_session;
}

int main(int argc, char** argv) {
  session_t *session = NULL;
  char packet[32];
  char buf[32];
  while(1) {
    int len = read(0, buf, 32);
    if(len < 32) {
      return 1;
    }
    for(int i = 0; i < 32; i++) {
      packet[i] = buf[i];
    }
    session = process(packet, session);
    if(session == NULL) {
      return 0;
    }
    printf("%s (%d): %f\n", session->user->name, session->user->id, session->score);
  }
}

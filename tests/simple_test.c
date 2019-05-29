#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MSG_LEN 16

struct data{
  int a;
  char c;
};

char msgSecret[] = "This is the secret message";
char msgDefault[] = "This is the default message";

char *print_secr(char *msg_sec, char *message, int  num) {
  char *ret_secr = malloc (sizeof(char) * 4);
  memcpy(ret_secr, "GOOD", 4);

  printf("Congrats! %s. Your input is %s \n", msg_sec, message);
  
  return ret_secr;
}

int print_default() {
  printf("Nothing will happen today! %s\n", msgDefault);
  return 0;
}

void crash_me() {
  struct data *data_pointer;
  data_pointer = (struct data *)malloc(sizeof(struct data));
  data_pointer->a = 5;
  data_pointer = NULL;
  data_pointer->a = 1;
}

int main(int argc, char **argv) {
  char message[MSG_LEN];
  char *ret_secr = NULL;

  printf("Please enter a message: \n"); 
  fgets(message, sizeof(message), stdin);

  int local_len = strlen(message);
  message[local_len-1] = '\0';
 
  if (!strcmp(message, "coverage")) {
    ret_secr = print_secr(msgSecret, message, 2);
    printf("Very %s!\n", ret_secr);
  } else if (!strcmp(message, "crash")) {
    crash_me();
  } else {
    print_default();
  }

  return 0;
}

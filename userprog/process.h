#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);

struct EXIT
{
	int pid;
	int value;
	struct semaphore sema_wait;
	int num;
	struct lock nextlock;
	struct list_elem elem;
	struct lock *locks;
};

void process_activate(void);


#endif /* userprog/process.h */

#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "lib/string.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"

struct lock f_lock;  /* lock for file */
static void syscall_handler(struct intr_frame *);
bool is_valid_range(const void * vaddr, unsigned size);


void
syscall_init(void)
{
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&f_lock);
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{

	if (is_valid_range((int *)f->esp, 0)==false)
		exit(-1);

	struct thread *t = thread_current();
	t->sys = true;

	int * esp = (int *)f->esp;
	int syscall_num = *esp;

	switch (syscall_num) /* Classfying syscall cases */
	{

	case SYS_WAIT:
		f->eax = (unsigned int)wait((int)*(esp+1));
		break;

	case SYS_CREATE:
		f->eax = (unsigned int)create((const char*)*(esp+1), (unsigned)*(esp+2));
		break;

	case SYS_REMOVE:
		f->eax = (unsigned int)remove((const char*)*(esp+1));
		break;

	case SYS_OPEN:
		f->eax = (unsigned int)open((const char*)*(esp+1));
		break;

	case SYS_READ:
		f->eax = (unsigned int)read((int)*(esp+1), (void*)*(esp+2), (unsigned)*(esp+3));
		break;

	case SYS_WRITE:
		f->eax = (unsigned int)write((int)*(esp+1), (const void*)*(esp+2), (unsigned)*(esp+3));
		break;

	case SYS_EXEC:
		f->eax = (unsigned int)exec((char*)*(esp+1));
		break;

	case SYS_SEEK:
		seek((int)*(esp+1), (unsigned)*(esp+2));
		break;

	case SYS_TELL:
		f->eax = (unsigned int)tell((int)*(esp+1));
		break;

	case SYS_CLOSE:
		close((int)*(esp+1));
		break;
	case SYS_HALT:
		halt();
		break;

	case SYS_EXIT:
		exit(*(esp+1));
		break;

	case SYS_FILESIZE:
		f->eax = (unsigned int)filesize((int)*(esp+1));
		break;

	default:
		break;
	}
	t->sys = false;
}


void halt(void)
{
	power_off();
}

pid_t
exec(const char *cmd_line)
{
	if (is_valid_range(cmd_line, 0)==false || is_valid_range(cmd_line, strlen(cmd_line))==false )
		exit(-1);

	char file_path[15];
	char * start = cmd_line; 
	char * end;
	while (*start == ' ')
		start++;
	end = start;
	while (*end != ' ' && *end != '\0')
		end++;
	strlcpy(file_path, start, end-start+1);

	/* Lock on process_execute since it needs to open the executable file */
	a();
	struct file *f = filesys_open(file_path);
	if (f == NULL)
	{
		b();
		return -1;
	}
	pid_t pid = (pid_t)process_execute(cmd_line);
	b();

	if (pid == (pid_t)TID_ERROR)
		return -1;
	return pid;
}

void
exit(int status)
{
	struct thread * cur_thread = thread_current();
	cur_thread->how_exited->value = status;
	thread_exit();
}

int
wait(pid_t pid)
{
	return process_wait(pid);
}

bool
create(const char *file, unsigned initial_size)
{

	if (is_valid_range(file, 0)==false || is_valid_range(file, strlen(file))==false)
		exit(-1);

	a();
	bool done = filesys_create(file, initial_size);
	b();
	return done;
}

bool
remove(const char *file)
{
	if (is_valid_range(file, 0)==false || is_valid_range(file, strlen(file))==false )
		exit(-1);

	a();
	bool done = filesys_remove(file);
	b();
	return done;
}

int
open(const char *file)
{
	if (is_valid_range(file, 0)==false || is_valid_range(file, strlen(file))==false )
		exit(-1);

	a();
	struct file *f = filesys_open(file);
	b();

	if (f == NULL)
		return -1;

	return add_fd(thread_current(), f);
}

int
filesize(int fd)
{
	struct thread* t = thread_current();
	if (fd == 0 || fd == 1 || is_valid_fd(t, fd)==false)
		exit(-1);

	a();
	int size = (int)file_length(t->f_handbox[fd]);
	b();

	return size;
}

int
read(int fd, void *buffer, unsigned size)
{
	if (is_valid_range(buffer, size)==false)
		exit(-1);

	else if (size < 0 || fd == STDOUT_FILENO)
		return -1;

	int final;
	struct thread *t = thread_current();
	final=0;
	if (fd == STDIN_FILENO)
	{
		unsigned i = 0;
		for (i = 0; i < size; i++)
		{
			final++;
			buffer++;
			*(int *)buffer = input_getc();
		}
		return final;
	}

	else if (is_valid_fd(t, fd))
	{
		struct file *f = t->f_handbox[fd];
		a();
		final = file_read(f, buffer, size);
		b();
		return final;
	}
	return -1;
}

int
write(int fd, const void *buffer, unsigned size)
{
	if (!is_valid_range(buffer, size))
		exit(-1);
	if (size <= 0)
		return 0;
	if (fd == STDIN_FILENO)
		return -1;

	int result = 0;
	struct thread *t = thread_current();
	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, size);
		result = size;
	}
	else if (is_valid_fd(t, fd))
	{
		struct file *file = t->f_handbox[fd];
		a();
		result = file_write(file, buffer, size);
		b();
	}
	return result;
}

void
seek(int fd, unsigned position)
{
	struct thread *t = thread_current();
	struct file *file = t->f_handbox[fd];

	if (!is_valid_fd || fd <2)
		exit(-1);

	a();
	file_seek(file, position);
	b();

}

unsigned
tell(int fd)
{
	struct thread *t = thread_current();
	struct file *file = t->f_handbox[fd];

	if (!is_valid_fd(t, fd) || fd <2)
		exit(-1);

	a();
	unsigned n = file_tell(file);
	b();
	return n;
}

void
close(int fd)
{
	struct thread* t = thread_current();
	if (fd == 0 || fd == 1 || is_valid_fd(t, fd)==false)
		return;

	a();
	file_close(t->f_handbox[fd]);
	b();
	remove_fd(t, fd);
}

bool
is_valid_fd (struct thread* thread, int fd)
{
  if (fd<0 || thread == NULL || fd >= thread->fhsize || thread->f_handbox[fd] == NULL)
    return false;
  return true;
}

bool
is_valid_range(const void * vaddr, unsigned size)
{
	/* False: 1. Null Pointer, 2. Pointing Kernel V.A.S 3. Pointing Unmapped V.M*/
	if (vaddr == NULL || !is_user_vaddr(vaddr) || !is_user_vaddr(vaddr + size) || vaddr< 0x08048000 || !pagedir_get_page(thread_current()->pagedir, vaddr) || !pagedir_get_page(thread_current()->pagedir, (vaddr + size)))
	{
		return false;
	}
	return true;
}

int
add_fd (struct thread* thread, struct file* file)
{
  int i;
  if (file == NULL || thread == NULL)
    exit (-1);

  if (thread->fhnum < thread->fhsize)
  {
    for (i=2; i < thread->fhsize; i++)
    {
      if (thread->f_handbox[i] == NULL)
      {
        thread->f_handbox[i] = file;
        thread->fhnum ++;
        return i;
      }
    }
    return -1;
  }
  
  return add_fd_helper(thread, file);
}


void
remove_fd (struct thread* thread, int fd)
{
  if (is_valid_fd (thread, fd)==false)
    exit (-1);
  thread->f_handbox[fd] = NULL;
  thread->fhnum --;
}

/* Lock functions */
void a(void)
{
	lock_acquire(&f_lock);
}
void b(void)
{
	lock_release(&f_lock);
}

int 
add_fd_helper (struct thread* thread, struct file* file)
{
  struct file **tempfh;
  if (thread->f_handbox != NULL)
  {
      thread->fhsize = thread->fhsize + thread->fhsize;
      tempfh = (struct file**)malloc (thread->fhsize * sizeof(struct file*));
      memcpy (tempfh, thread->f_handbox, thread->fhnum * sizeof(struct file*));
      memset (&tempfh[thread->fhnum], 0,thread->fhnum);

  }
  else
  {
      thread->fhsize = FILE_HDL_SIZE;
      tempfh = (struct file**) malloc (FILE_HDL_SIZE * sizeof(struct file*));
      memset (tempfh, 0, FILE_HDL_SIZE * sizeof(struct file*));
      thread->fhnum = 2;
  }
    thread->f_handbox = tempfh;
    thread->f_handbox[thread->fhnum] = file;
    return thread->fhnum;
}

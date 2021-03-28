#include <stdio.h>
#include <user/syscall.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"


static void syscall_handler (struct intr_frame *);
int* get_args (struct intr_frame *f, int n);
void sys_halt (void);
pid_t sys_exec(const char* cmdline);
int sys_wait(pid_t pid);
bool sys_create(const char* file, unsigned size);
bool sys_remove(const char* file);
int sys_open(const char * file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write (int fd, const void * buffer, unsigned size);
void sys_seek (int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
void validate_ptr (const void* ptr);
void validate_str (const void* str);
void validate_buffer (const void* buf, unsigned size);
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  int * args;
  int esp = page_ptr((const void *) f->esp);
  switch (* (int *) esp)
  {
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_EXIT:
      sys_exit(get_args(f, 1)[0]);
      break;
    case SYS_EXEC:
      args = get_args(f, 1);
      validate_str((const void*)args);
      args[0] = page_ptr((const void *)args[0]);
      f->eax = sys_exec((const char*) args[0]);
      break;
    case SYS_WAIT:
      args = get_args(f, 1);
      f-> eax = sys_wait(args[0]);
      break;
    case SYS_CREATE:
      args = get_args(f,2);
      f-> eax = sys_create((const char*)args[0], args[1]);
      break;
    case SYS_REMOVE:
      args = get_args(f, 1);
      validate_str((const void*)args[0]);
      args[0] = page_ptr((const void*)args[0]);
      f->eax = sys_remove((const char *)args[0]);
      break;
    case SYS_OPEN:
      args = get_args(f, 1);
      validate_str((const void*)args[0]);
      args[0] = page_ptr((const void*)args[0]);
      f->eax = sys_open((const char *)args[0]);
      break;
    case SYS_FILESIZE:
      args = get_args(f, 1);
      f->eax = sys_filesize((const char *)args[0]);
      break;
    case SYS_READ:
      args = get_args(f, 3);
      validate_buffer((const void *)args[1], (unsigned)args[2]);
      args[1] = page_ptr((const void *)args[1]);
      f->eax = sys_read(args[0], (void*) args[1], (unsigned)args[2]);
      break;
    case SYS_WRITE:
      args = get_args(f, 3);
      validate_buffer((const void *)args[1], (unsigned)args[2]);
      args[1] = page_ptr((const void *)args[1]);
      f->eax = sys_write(args[0], (void*) args[1], (unsigned)args[2]);
      break;
    case SYS_SEEK:
      args = get_args(f, 2);
      sys_seek(args[0], (unsigned)args[1]);
      break;
    case SYS_TELL:
      args = get_args(f, 1);
      f->eax = sys_tell((const char *)args[0]);
      break;
    case SYS_CLOSE:
      args = get_args(f, 1);
      sys_close(args[0]);
      break;
    default:
      break;
  }

}
// Used to get arguments from the command line
int *
get_args(struct intr_frame *f, int n){
  int args[n];
  int i;
  int * temp;
  for(i = 0; i<n; i++){
    temp = (int *) f->esp + i + 1;
    validate_ptr((const void *) temp);
    args[i] = *temp;
  }
  return args;
}
// Used to get args to call each function 
void
validate_str (const void* str)
{
    for (; * (char *) page_ptr(str) != 0; str = (char *) str + 1);
}
// used to validate pointers
void
validate_ptr (const void *ptr)
{
    if (ptr < ((void *) 0x08048000) || !is_user_vaddr(ptr))
    {
      // virtual memory address is not reserved for us (out of bound)
      sys_exit(-1);
    }
}
// Used to validate buffer
void
validate_buffer(const void* buf, unsigned size)
{
  unsigned i = 0;
  char* local_buffer = (char *)buf;
  for (; i < size; i++)
  {
    validate_ptr((const void*)local_buffer);
    local_buffer++;
  }
}

// Used to get page pointer
// source in the design document
int page_ptr(void *vaddr){
  void * ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if(!ptr)
    sys_exit(-1); // ( x ) < 0 means there is error
  return (int)ptr;
}

void
sys_halt (void)
{
  shutdown_power_off();
}

void
sys_exit (int status)
{
  thread *t = thread_current();
  if (status < 0)
  {
    status = -1;
  }
  printf("%s: exit(%d)", t->name, status);
}

int
sys_exec(const char* cmd_line)
{
  int pid = process_execute(cmd_line);

}

int
sys_wait(pid_t pid)
{
  return process_wait(pid);
}

bool
sys_create(const char* file, unsigned size)
{
  return false;
}
bool
sys_remove(const char* file)
{

}
int
sys_open(const char *file)
{

}
int
sys_filesize(int fd)
{

}

int
sys_read(int fd, void *buffer, unsigned size)
{

}

int 
sys_write (int fd, const void * buffer, unsigned size)
{

}

void
sys_seek (int fd, unsigned position)
{

}

unsigned
sys_tell(int fd)
{

}

void
sys_close(int fd)
{

}


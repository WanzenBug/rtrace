#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#define __USE_GNU 1
#include <sys/uio.h>
#undef __USE_GNU

long wrapped_fixed_arg_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) {
  return ptrace(request, pid, addr, data);
}

typedef struct {
  pid_t pid;
  char exited;
  int exit_status;
  char terminated_by_signal;
  int termination_signal;
  char stopped;
  char syscalled;
  char no_child;
  int signal;
  char event;
} waitpid_t;

waitpid_t wrapped_waitpid(pid_t pid, int options) {
  int status = 0;
  pid_t changed = waitpid(pid, &status, options);
  waitpid_t ret = {
      .pid = changed,
      .exited = WIFEXITED(status),
      .exit_status = WEXITSTATUS(status),
      .terminated_by_signal = WIFSIGNALED(status),
      .termination_signal = WTERMSIG(status),
      .stopped = WIFSTOPPED(status),
      .syscalled = WSTOPSIG(status) == (SIGTRAP | 0x80),
      .no_child = errno == ECHILD,
      .signal = WSTOPSIG(status),
      .event = status >> 16,
  };
  return ret;
}

ssize_t wrapped_process_vm_readv_string(pid_t pid, char *dest, ssize_t length, const void* source) {
  struct iovec local = {
      .iov_base = dest,
      .iov_len = length,
  };

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size == -1) {
    return -1;
  }

  struct iovec *remote = malloc(sizeof(struct iovec) * ((length - 1) / page_size + 2));
  if (remote == NULL) {
    return -1;
  }
  size_t source_end = (size_t)source + length;
  size_t aligned_source_start = (size_t)source;
  size_t aligned_source_end = ((size_t)source & (~((size_t) page_size - 1))) + (size_t) page_size;
  size_t count = 0;
  while (source_end > aligned_source_end) {
    remote[count].iov_base = (void*)aligned_source_start;
    remote[count].iov_len = aligned_source_end - aligned_source_start;
    count += 1;
    aligned_source_start = aligned_source_end;
    aligned_source_end = aligned_source_start + (size_t) page_size;
  }

  ssize_t ret = process_vm_readv(pid, &local, 1, remote, count, 0);
  free(remote);

  return ret;
}

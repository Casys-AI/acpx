#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define GROUP_POLL_TIMEOUT_MS 100
#define TERM_GRACE_POLLS 10
#define KILL_RETRY_POLLS 10
#define KILL_RETRY_ROUNDS 10

static int parse_pgid(const char *value, pid_t *pgid) {
  errno = 0;
  char *end = NULL;
  long parsed = strtol(value, &end, 10);
  if (errno == ERANGE || end == value || *end != '\0' || parsed <= 1) {
    return -1;
  }

  pid_t narrowed = (pid_t)parsed;
  if ((long)narrowed != parsed || narrowed == getpid() || narrowed == getpgrp()) {
    return -1;
  }

  *pgid = narrowed;
  return 0;
}

static int process_group_alive(pid_t pgid) {
  if (kill(-pgid, 0) == 0) {
    return 1;
  }
  if (errno == EPERM) {
    return 1;
  }
  if (errno == ESRCH) {
    return 0;
  }
  return 1;
}

static int process_alive(pid_t pid) {
  if (kill(pid, 0) == 0) {
    return 1;
  }
  if (errno == EPERM) {
    return 1;
  }
  if (errno == ESRCH) {
    return 0;
  }
  return 1;
}

static void sleep_ms(long milliseconds) {
  struct timespec delay = {
      .tv_sec = milliseconds / 1000,
      .tv_nsec = (milliseconds % 1000) * 1000000L,
  };
  while (nanosleep(&delay, &delay) == -1 && errno == EINTR) {
  }
}

static void reap_group(pid_t pgid) {
  (void)kill(-pgid, SIGTERM);
  for (int poll = 0; poll < TERM_GRACE_POLLS; poll += 1) {
    if (!process_group_alive(pgid)) {
      return;
    }
    sleep_ms(20);
  }

  for (int round = 0; round < KILL_RETRY_ROUNDS; round += 1) {
    if (!process_group_alive(pgid)) {
      return;
    }
    (void)kill(-pgid, SIGKILL);
    for (int poll = 0; poll < KILL_RETRY_POLLS; poll += 1) {
      if (!process_group_alive(pgid)) {
        return;
      }
      sleep_ms(20);
    }
  }
}

static int announce_armed(void) {
  static const char message[] = "ARMED\n";
  size_t written = 0;
  while (written < sizeof(message) - 1) {
    ssize_t result = write(STDOUT_FILENO, message + written, sizeof(message) - 1 - written);
    if (result == -1 && errno == EINTR) {
      continue;
    }
    if (result <= 0) {
      return -1;
    }
    written += (size_t)result;
  }
  (void)close(STDOUT_FILENO);
  return 0;
}

static int wait_for_owner_pipe(pid_t bridge_pgid) {
  struct pollfd pfd = {
      .fd = STDIN_FILENO,
      .events = POLLIN,
  };
  char buffer[32];

  for (;;) {
    int ready = poll(&pfd, 1, GROUP_POLL_TIMEOUT_MS);
    if (ready == -1) {
      if (errno == EINTR) {
        continue;
      }
      return 1;
    }

    if (ready == 0) {
      if (!process_alive(bridge_pgid)) {
        return process_group_alive(bridge_pgid) ? 1 : 0;
      }
      continue;
    }

    if ((pfd.revents & POLLIN) != 0) {
      ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
      if (count == -1 && errno == EINTR) {
        continue;
      }
      if (count <= 0) {
        return process_group_alive(bridge_pgid) ? 1 : 0;
      }
      if (memchr(buffer, 'R', (size_t)count) != NULL) {
        return 0;
      }
    }

    if ((pfd.revents & POLLHUP) != 0) {
      return process_group_alive(bridge_pgid) ? 1 : 0;
    }

    if ((pfd.revents & (POLLERR | POLLNVAL)) != 0) {
      /* A broken lifeline must fail safe by reaping the managed group. */
      return 1;
    }

    if (!process_alive(bridge_pgid)) {
      return process_group_alive(bridge_pgid) ? 1 : 0;
    }
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: lifeline <bridgePgid>\n");
    return 2;
  }

  pid_t bridge_pgid = 0;
  if (parse_pgid(argv[1], &bridge_pgid) != 0) {
    fprintf(stderr, "invalid bridge pgid\n");
    return 2;
  }
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    reap_group(bridge_pgid);
    return 1;
  }
  if (announce_armed() != 0) {
    reap_group(bridge_pgid);
    return 1;
  }

  int result = wait_for_owner_pipe(bridge_pgid);
  if (result == 1) {
    reap_group(bridge_pgid);
  }
  return result == 0 ? 0 : 1;
}

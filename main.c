#include <dirent.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
enum state { NO_ERROR, PARSE_FILE_ERROR };
#define MAX_FIELDS 52
#define INITIAL_CAPACITY 1024

struct termios oldt, newt;
// Global dynamic arrays to store previous process CPU times and validity flags.
unsigned long *prev_proc_cpu_time = NULL;
bool *valid_proc = NULL;
// Keep track of the current capacity (number of elements allocated).
size_t capacity = 0;

unsigned long long prev_total_cpu_time = 0;

DIR *d;
struct cpu_stats_info {
  char cpu_stat_line_str[512];
  unsigned long long user;
  unsigned long long nice;
  unsigned long long system;
  unsigned long long idle;
  unsigned long long iowait;
  unsigned long long irq;
  unsigned long long softirq;
  unsigned long long steal;
};
struct cpu_stats_info *cpu_info = NULL;
struct process_info {
  unsigned long pid;
  char process_name[50];
  char command_line_args[256];
  char state;
  unsigned long utime;
  unsigned long stime;
  double rss;
};

void free_arrays() {
  if (valid_proc) {
    free(valid_proc);
  }
  if (prev_proc_cpu_time) {
    free(prev_proc_cpu_time);
  }
}

void exit_with_error(const char *message, ...) {
  va_list args;
  va_start(args, message);
  vfprintf(stderr, message, args);
  va_end(args);
  free_arrays();
  if (d) {
    closedir(d);
  }
  if (cpu_info) {
    free(cpu_info);
  }
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  exit(EXIT_FAILURE);
}
void str_trim(char *str) {
  size_t len = strlen(str);
  while (len > 0 && str[len - 1] == ' ') {
    str[len - 1] = '\0';
    len--;
  }
}

enum state parse_stat_file(const char *buffer, int pid,
                           struct process_info *info) {
  // find first and last ()

  char *start = strchr(buffer, '(');
  char *end = strrchr(buffer, ')');
  if ((!start || !end) || (end < start)) {
    return PARSE_FILE_ERROR;
  }

  size_t comm_len = end - start - 1;
  if (comm_len > sizeof(info->process_name)) {
    comm_len = sizeof(info->process_name) - 1;
  }
  strncpy(info->process_name, start + 1, comm_len);
  info->process_name[comm_len] = '\0';

  char state;
  int n;
  if (sscanf(end + 2, "%c%n", &state, &n) != 1) {
    return PARSE_FILE_ERROR;
  }
  char *rest = end + 2 + n;

  int ppid, pgrp, session, tty_nr, tpgid;
  unsigned int flags;
  unsigned long minflt, cminflt, majflt, cmajflt;
  unsigned long utime, stime;
  long cutime, cstime, priority, nice, num_threads, itrealvalue;
  unsigned long long starttime;
  unsigned long vsize;
  long rss;

  int count =
      sscanf(rest,
             "%d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld "
             "%ld %llu %lu %ld",
             &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags, &minflt, &cminflt,
             &majflt, &cmajflt, &utime, &stime, &cutime, &cstime, &priority,
             &nice, &num_threads, &itrealvalue, &starttime, &vsize, &rss);
  // TODO
  if (count < 21) {
    fprintf(stderr, "Error parsing remaining fields (only got %d fields)\n",
            count);
    return PARSE_FILE_ERROR;
  }

  info->utime = utime;
  info->stime = stime;
  info->pid = pid;
  info->state = state;
  info->rss =
      (rss > 0) ? (double)(rss * sysconf(_SC_PAGESIZE)) / (1024 * 1024) : 0;
  return NO_ERROR;
}

// Function to ensure our dynamic arrays can index at least up to pid.
void ensure_capacity(size_t pid) {
  if (pid < capacity) {
    return;
  }
  size_t new_capacity = (capacity == 0) ? INITIAL_CAPACITY : capacity;
  while (pid >= new_capacity) {
    new_capacity *= 2; // Double the capacity until it fits the pid.
  }
  unsigned long *new_prev =
      realloc(prev_proc_cpu_time, new_capacity * sizeof(unsigned long));
  if (!new_prev) {
    perror("realloc prev_proc_cpu_time");
    exit(EXIT_FAILURE);
  }
  // Initialize new elements to 0.
  for (size_t i = capacity; i < new_capacity; i++) {
    new_prev[i] = 0;
  }
  prev_proc_cpu_time = new_prev;

  bool *new_valid = realloc(valid_proc, new_capacity * sizeof(bool));
  if (!new_valid) {
    perror("realloc new valid");
    exit(EXIT_FAILURE);
  }
  // Initialize new elements to false.
  for (size_t i = capacity; i < new_capacity; i++) {
    new_valid[i] = false;
  }
  valid_proc = new_valid;
  capacity = new_capacity;
}

struct cpu_stats_info *get_cpu_stats() {
  FILE *cpu_stats_file = fopen("/proc/stat", "r");
  if (!cpu_stats_file) {
    exit_with_error("couldn't open /proc/stat file\n", NULL);
  }
  struct cpu_stats_info *cpu_info = malloc(sizeof(struct cpu_stats_info));
  if (!cpu_info) {
    fclose(cpu_stats_file);
    exit_with_error("couldn't allocate memory\n", NULL);
  }
  if (fgets(cpu_info->cpu_stat_line_str, sizeof(cpu_info->cpu_stat_line_str),
            cpu_stats_file) != NULL) {
    // because structure like this -> cpu  1887166 11639 956416 90543274 33256 0
    // 183585 0 0 0 we want to skip the "cpu "
    if (strncmp(cpu_info->cpu_stat_line_str, "cpu ", 4) == 0) {
      sscanf(cpu_info->cpu_stat_line_str + 5,
             "%llu %llu %llu %llu %llu %llu %llu %llu", &cpu_info->user,
             &cpu_info->nice, &cpu_info->system, &cpu_info->idle,
             &cpu_info->iowait, &cpu_info->irq, &cpu_info->softirq,
             &cpu_info->steal);
    }
  } else {
    fclose(cpu_stats_file);
    free(cpu_info);
    exit_with_error("couldn't read string from stat file\n");
  }
  fclose(cpu_stats_file);
  return cpu_info;
}

unsigned long long
calculate_cpu_time_total(const struct cpu_stats_info *cpu_info) {
  return cpu_info->user + cpu_info->nice + cpu_info->system + cpu_info->idle +
         cpu_info->iowait + cpu_info->irq + cpu_info->softirq + cpu_info->steal;
}

char *read_command_line(long pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%lu/cmdline", pid);
  FILE *file_ptr = fopen(path, "r");
  if (!file_ptr) {
    fprintf(stderr, "Couldn't read from /proc/%lu/cmdline file\n", pid);
    return NULL;
  }
  char *buffer = calloc(1, 4096);
  if (!buffer) {
    fprintf(stderr, "Couldn't allocate memory\n");
    fclose(file_ptr);
    exit(EXIT_FAILURE);
  }
  memset(buffer, 0, 4096);
  size_t bytes_read = fread(buffer, 1, 4095, file_ptr);
  if (bytes_read <= 0) {
    fclose(file_ptr);
    free(buffer);
    return NULL;
  }
  fclose(file_ptr);

  buffer[bytes_read] = '\0';
  return buffer;
}

void read_stat_file_data(long pid, struct process_info *info) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%lu/stat", pid);
  FILE *file_ptr = fopen(path, "r");
  if (!file_ptr) {
    free(info);
    exit_with_error("Couldn't open /proc/%lu/stat file\n", pid);
  }
  char *buffer = malloc(1024);
  if (!buffer) {
    fclose(file_ptr);
    free(info);
    exit_with_error("Couldn't allocate memory\n");
  }
  if (!fgets(buffer, 1024, file_ptr)) {
    free(buffer);
    free(info);
    fclose(file_ptr);
    exit_with_error("coudn't read from /proc/%lu/stat file\n", pid);
  }

  enum state state = parse_stat_file(buffer, pid, info);

  if (state == PARSE_FILE_ERROR) {
    free(buffer);
    free(info);
    fclose(file_ptr);
    exit_with_error("couldn 't parse proc/%lu/stat file\n", pid, NULL);
  }

  free(buffer);
  fclose(file_ptr);
}

void handle_exit(int sig) {
  if (prev_proc_cpu_time) {
    free(prev_proc_cpu_time);
  }
  if (valid_proc) {
    free(valid_proc);
  }
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  exit(0);
}
int main() {
  // Register signal handler (for SIGINT, for example).
  signal(SIGINT, handle_exit);

  // Set terminal to non-canonical mode so that key presses are detected
  // immediately.
  tcgetattr(STDIN_FILENO, &oldt); // Save current terminal settings
  newt = oldt;
  newt.c_lflag &= ~(ICANON | ECHO); // Disable canonical mode and echo
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  capacity = INITIAL_CAPACITY;
  prev_proc_cpu_time = malloc(capacity * sizeof(unsigned long));
  valid_proc = malloc(capacity * sizeof(bool));
  if (!prev_proc_cpu_time || !valid_proc) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  for (size_t i = 0; i < capacity; i++) {
    prev_proc_cpu_time[i] = 0;
    valid_proc[i] = false;
  }

  // Main loop
  while (1) {
    system("clear");
    //   printf("\033[H\033[J");

    printf("+------------------------------------------------------------------"
           "-----"
           "----"
           "---------------\n");
    printf("|%-52.50s|%-9s|%-s|%-s|%-8s|%-s\n", "PROCESS NAME", "PID",
           "CPU (%)", "STATE", "RSS(mb)", "CMD");
    printf("+------------------------------------------------------------------"
           "-----"
           "----"
           "---------------\n");

    // Get the current overall CPU stats and compute total CPU time.
    cpu_info = get_cpu_stats();
    unsigned long long total_cpu_time = calculate_cpu_time_total(cpu_info);

    struct dirent *dir;
    d = opendir("/proc");

    if (d) {
      while ((dir = readdir(d)) != NULL) {
        char *next = NULL;
        char *process_args = NULL;
        char *process_name = NULL;
        long val = strtol(dir->d_name, &next, 10);
        if (next != dir->d_name && (*next == '\0' || *next == '\n')) {
          struct process_info *info = calloc(1, sizeof(struct process_info));
          if (!info) {
            fprintf(stderr, "couldn't allocate memory for process info\n");
            continue;
          }

          read_stat_file_data(val, info);
          process_args = read_command_line(val);

          if (process_args) {
            strncpy(info->command_line_args, process_args,
                    sizeof(info->command_line_args) - 1);
            info->command_line_args[sizeof(info->command_line_args) - 1] = '\0';
          } else {
            strcpy(info->command_line_args, "[]");
          }

          // Calculate cumulative process CPU time (user + system).
          unsigned long current_proc_time = info->utime + info->stime;
          double usage_percent = 0.0;

          // Ensure our dynamic arrays are large enough.
          ensure_capacity((size_t)val);

          if (valid_proc[val]) {
            unsigned long proc_diff =
                current_proc_time - prev_proc_cpu_time[val];

            unsigned long long total_diff =
                total_cpu_time - prev_total_cpu_time;
            if (total_diff > 0) {
              usage_percent = (proc_diff / (double)total_diff) * 100.0;
            }
          } else {
            // First time seeing this process.
            valid_proc[val] = true;
            usage_percent = 0.0;
          }
          // Update the stored CPU time for this process.
          prev_proc_cpu_time[val] = current_proc_time;

          printf("[%-50.50s] | %-6lu  | %-5.2f | %-3c | %-7.2f| %-.140s\n",
                 info->process_name, info->pid, usage_percent, info->state,
                 info->rss, info->command_line_args);

          if (process_args) {
            free(process_args);
          }
          free(info);
        }
      }
      if (d) {
        closedir(d);
      }
    }
    if (cpu_info) {
      free(cpu_info);
    }

    // Update the global previous total CPU time.
    prev_total_cpu_time = total_cpu_time;

    // --- Check for key press without blocking ---
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    struct timeval tv = {0, 0}; // Zero timeout for non-blocking check.
    if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0) {
      char ch;
      read(STDIN_FILENO, &ch, 1);
      if (ch == 'q' || ch == 'Q') {
        break; // Exit the main loop.
      }
    }

    printf("+------------------------------------------------------------------"
           "-----"
           "----"
           "---------------\n");
    printf("press q or CTRL-C to exit \n");
    usleep(400000); // Sleep for 400ms between updates.
  }

  // Restore the original terminal settings.
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

  // Cleanup dynamic arrays.
  free(prev_proc_cpu_time);
  free(valid_proc);

  return 0;
}

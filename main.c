#include <dirent.h>
#include <signal.h>
#include <stdbool.h> // for bool type
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#define UTIME_INDEX 13
#define STIME_INDEX 14
#define INITIAL_CAPACITY 1024

// Global dynamic arrays to store previous process CPU times and validity flags.
unsigned long *prev_proc_cpu_time = NULL;
bool *valid_proc = NULL;
// Keep track of the current capacity (number of elements allocated).
size_t capacity = 0;

// Global variable to store previous total CPU time.
unsigned long long prev_total_cpu_time = 0;

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

struct process_info {
  unsigned long pid;
  char process_name[150];
  char command_line_args[256];
  char state;
  unsigned long utime;
  unsigned long stime;
};

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
    perror("realloc valid_proc");
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
    perror("Failed to open /proc/stat");
    exit(EXIT_FAILURE);
  }
  struct cpu_stats_info *cpu_info = malloc(sizeof(struct cpu_stats_info));
  if (!cpu_info) {
    exit(EXIT_FAILURE);
  }
  if (fgets(cpu_info->cpu_stat_line_str, sizeof(cpu_info->cpu_stat_line_str),
            cpu_stats_file)) {
    if (strncmp(cpu_info->cpu_stat_line_str, "cpu ", 4) == 0) {
      sscanf(cpu_info->cpu_stat_line_str + 5,
             "%llu %llu %llu %llu %llu %llu %llu %llu", &cpu_info->user,
             &cpu_info->nice, &cpu_info->system, &cpu_info->idle,
             &cpu_info->iowait, &cpu_info->irq, &cpu_info->softirq,
             &cpu_info->steal);
    }
  }
  fclose(cpu_stats_file);
  return cpu_info;
}

unsigned long long
calculate_cpu_time_total(const struct cpu_stats_info *cpu_info) {
  return cpu_info->user + cpu_info->nice + cpu_info->system + cpu_info->idle +
         cpu_info->iowait + cpu_info->irq + cpu_info->softirq + cpu_info->steal;
}

char *read_process_name(long pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%lu/comm", pid);
  FILE *file_ptr = fopen(path, "r");
  if (!file_ptr) {
    return NULL;
  }
  char *buffer = malloc(1024);
  if (!buffer) {
    perror("malloc");
    return NULL;
  }
  size_t bytes_read = fread(buffer, 1, 1023, file_ptr);
  if (bytes_read <= 0) {
    fclose(file_ptr);
    free(buffer);
    return NULL;
  }
  fclose(file_ptr);
  buffer[bytes_read] = '\0';
  return buffer;
}

char *read_command_line(long pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%lu/cmdline", pid);
  FILE *file_ptr = fopen(path, "r");
  if (!file_ptr) {
    return NULL;
  }
  char *buffer = malloc(4096);
  if (!buffer) {
    perror("malloc");
    fclose(file_ptr);
    return NULL;
  }
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

void read_utime_stime(long pid, struct process_info *info) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%lu/stat", pid);
  FILE *file_ptr = fopen(path, "r");
  if (!file_ptr) {
    return;
  }
  char *buffer = malloc(1024);
  if (!buffer) {
    fclose(file_ptr);
    perror("malloc");
    return;
  }
  if (!fgets(buffer, 1024, file_ptr)) {
    free(buffer);
    fclose(file_ptr);
    return;
  }
  // Skip until after the closing parenthesis (process name)
  char *ptr = buffer;
  while (*ptr != ')' && *ptr != '\0') {
    ptr++;
  }
  if (*ptr == ')')
    ptr++;
  if (*ptr == ' ')
    ptr++;

  // Read process state
  sscanf(ptr, "%c", &info->state);

  // Declare dummy variables to skip unnecessary fields.
  unsigned long dummy;
  unsigned long parent_process_pid;
  unsigned long pgrp;
  unsigned long session_id;
  unsigned long tty_nr;
  unsigned long tpgid;
  unsigned long flags;
  unsigned long minflt;
  unsigned long cminflt;
  unsigned long majflt;
  unsigned long cmajflt;

  // Skip process state (already read) then parse until utime and stime.
  sscanf(ptr, "%*c %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
         &parent_process_pid, &pgrp, &session_id, &tty_nr, &tpgid, &flags,
         &minflt, &cminflt, &majflt, &cmajflt, &info->utime, &info->stime);

  info->pid = pid;
  free(buffer);
  fclose(file_ptr);
}

void handle_exit(int sig) {
  printf("\nCaught signal %d! Cleaning up...\n", sig);
  exit(0); // Cleanup handlers registered with atexit() will run here.
}

int main() {
  // Register signal handler (for SIGINT, for example).
  signal(SIGINT, handle_exit);

  // Set terminal to non-canonical mode so that key presses are detected
  // immediately.
  struct termios oldt, newt;
  tcgetattr(STDIN_FILENO, &oldt); // Save current terminal settings
  newt = oldt;
  newt.c_lflag &= ~(ICANON | ECHO); // Disable canonical mode and echo
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  // Initialize our dynamic arrays.
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
    printf("+----------+-----------+---------------+\n");
    printf("| PID      | CPU Usage | Process Name  |\n");
    printf("+----------+-----------+---------------+\n");

    // Get the current overall CPU stats and compute total CPU time.
    struct cpu_stats_info *cpu_info = get_cpu_stats();
    unsigned long long total_cpu_time = calculate_cpu_time_total(cpu_info);

    DIR *d;
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
          if (!info)
            continue;

          process_args = read_command_line(val);
          process_name = read_process_name(val);

          if (process_args) {
            strncpy(info->command_line_args, process_args,
                    sizeof(info->command_line_args) - 1);
            info->command_line_args[sizeof(info->command_line_args) - 1] = '\0';
          } else {
            strcpy(info->command_line_args, "[]");
          }

          if (process_name) {
            strncpy(info->process_name, process_name,
                    sizeof(info->process_name) - 1);
            info->process_name[sizeof(info->process_name) - 1] = '\0';
          } else {
            strcpy(info->process_name, "[]");
          }

          read_utime_stime(val, info);

          // Calculate cumulative process CPU time (user + system).
          unsigned long current_proc_time = info->utime + info->stime;
          double usage_percent = 0.0;

          // Ensure our dynamic arrays are large enough.
          ensure_capacity((size_t)val);

          if (valid_proc[val]) {
            // Calculate the difference in process time between iterations.
            unsigned long proc_diff =
                current_proc_time - prev_proc_cpu_time[val];
            // Calculate the overall CPU time difference.
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

          printf("PID: %-5lu | CPU: %-.2f | NAME: %-13s\n", info->pid,
                 usage_percent, info->process_name);

          if (process_name)
            free(process_name);
          if (process_args)
            free(process_args);
          free(info);
        }
      }
      closedir(d);
    }
    free(cpu_info);

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

    printf("+----------+-----------+---------------+\n");
    usleep(400000); // Sleep for 400ms between updates.
  }

  // Restore the original terminal settings.
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

  // Cleanup dynamic arrays.
  free(prev_proc_cpu_time);
  free(valid_proc);

  return 0;
}

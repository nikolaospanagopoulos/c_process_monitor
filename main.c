#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UTIME_INDEX 13
#define STIME_INDEX 14
#define MAX_PID 32768

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
  unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
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
    perror("fopen");
    return NULL;
  }
  // maybe enlarge later?
  char *buffer = (char *)malloc(1024);
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

  // printf("Process name for proc %lu: %s\n", pid, buffer);

  return buffer;
}

char *read_command_line(long pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%lu/cmdline", pid);
  FILE *file_ptr = fopen(path, "r");
  if (!file_ptr) {
    perror("fopen");
    return NULL;
  }
  char *buffer = (char *)malloc(4096);
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

  // printf("Command line args for PID %lu: %s\n", pid, buffer);

  return buffer;
}

void read_utime_stime(long pid, struct process_info *info) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%lu/stat", pid);
  FILE *file_ptr = fopen(path, "r");
  if (!file_ptr) {
    perror("fopen");
    return;
  }
  char *buffer = (char *)malloc(1024);
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

  int scanned_pid;

  char process_state;

  unsigned long dummy;

  // handle ) or ))
  char *ptr = buffer;
  while (*ptr != ')' && *ptr != '\0') {
    ptr++;
  }
  ptr++;
  if (*(ptr) == ')' && *ptr != '\0') {
    ptr++;
  }
  ptr++;

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

  info->pid = pid;

  sscanf(ptr, "%c %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
         &info->state, &parent_process_pid, &pgrp, &session_id, &tty_nr, &tpgid,
         &flags, &minflt, &cminflt, &majflt, &cmajflt, &info->utime,
         &info->stime);

  free(buffer);
  fclose(file_ptr);
}

int main() {
  while (1) {
    system("clear");
    struct cpu_stats_info *cpu_info = get_cpu_stats();

    unsigned long long total_cpu_time = calculate_cpu_time_total(cpu_info);

    // printf("total cpu time %llu", total_cpu_time);

    DIR *d;
    struct dirent *dir;
    d = opendir("/proc");
    if (d) {
      while ((dir = readdir(d)) != NULL) {
        char *next = NULL;
        char *process_args = NULL;
        char *process_name = NULL;
        long val = strtol(dir->d_name, &next, 10);
        if (next != dir->d_name || *next == '\0') {
          // printf("%s\n", dir->d_name);
          struct process_info *info =
              (struct process_info *)calloc(1, sizeof(struct process_info));
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
            info->command_line_args[sizeof(info->process_name) - 1] = '\0';
          } else {
            strcpy(info->process_name, "[]");
          }

          read_utime_stime(val, info);

          printf("PID: %lu |name: %s| utime: %lu | stime: %lu\n", info->pid,
                 info->process_name, info->utime, info->stime);

          if (process_name) {
            free(process_name);
          }
          free(info);
        }
      }
      closedir(d);
    }

    free(cpu_info);
    usleep(500000);
  }
  return 0;
}

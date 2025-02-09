# Linux Performance Monitor

A lightweight, terminal-based Linux process and CPU usage monitor built in C using `/proc` filesystem.

## 📌 Features

✅ Displays active processes with:

- **Real-time Process Monitoring**: Displays a live list of running processes.
- **CPU Usage**: Calculates and displays the CPU usage percentage for each process.
- **Memory Usage**: Shows the Resident Set Size (RSS) in megabytes for each process.
- **Process State**: Indicates the current state of each process (e.g., running, sleeping).

---

## Prerequisites

- **Linux Environment**: This tool is designed to run on Linux systems.
- **GCC Compiler**: Ensure you have GCC installed to compile the C code.

## 🛠️ Installation & Usage

### 1️⃣ **Clone the repository**

```sh
git clone https://github.com/nikolaospanagopoulos/linux-performance-monitor.git
```

### 2️⃣ **Compile**

```sh
gcc -o main main.c
```

### 3️⃣ **Run**

```sh
./main
```

### 4️⃣ **Exit**

```sh
q
```

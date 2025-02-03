# Linux Performance Monitor

A lightweight, terminal-based Linux process and CPU usage monitor built in C using `/proc` filesystem.

## 📌 Features

✅ Displays active processes with:

- **PID (Process ID)**
- **CPU Usage (%)**
- **Process Name**
- **Command line args**

✅ Dynamically allocates memory to track CPU usage efficiently.  
✅ Uses **non-blocking input handling** for smooth updates.  
✅ Supports **keyboard interrupt (`Ctrl + C`)** and **'q' key** for quitting.

---

## 🛠️ Installation & Usage

### 1️⃣ **Clone the repository**

```sh
git clone https://github.com/nikolaospanagopoulos/linux-performance-monitor.git
cd linux-performance-monitor
gcc -o main main.c
./main
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

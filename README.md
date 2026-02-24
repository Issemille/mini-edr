# mini-edr

A minimal Linux Endpoint Detection & Response (EDR) prototype built with eBPF.

This project hooks into the Linux kernel using eBPF to monitor process execution events in real time and streams them to a userspace agent for logging and analysis.

## Features

- Hooks `sched_process_exec` tracepoint using eBPF
- Captures process metadata:
  - PID
  - UID
  - process name (`comm`)
- Sends events from kernel → userspace via ring buffer
- Logs telemetry to CSV (`events.csv`)
- Real-time event monitoring

Example output:

PID: 1234 UID: 1000 COMM: ls  
PID: 1235 UID: 1000 COMM: bash  

## Architecture

Kernel space:
- eBPF program attached to exec tracepoint
- Ring buffer map for event transport

User space:
- libbpf loader
- ring buffer reader
- CSV logging agent

Data flow:

Process exec  
→ kernel tracepoint  
→ eBPF program  
→ ring buffer  
→ userspace agent  
→ CSV log  

## Project goals

This project is a learning exercise to understand:

- Linux kernel observability
- eBPF programming
- kernel ↔ userspace communication
- telemetry pipelines
- foundations of EDR systems

Future goals:

- parent process tracking (PPID)
- network telemetry
- anomaly detection
- real-time alerting
- ML-based behavioral analysis

## Build

Compile eBPF program:

```bash
clang -O2 -g -target bpf \
  -I/usr/include/aarch64-linux-gnu \
  -c ebpf/exec.bpf.c \
  -o ebpf/exec.bpf.o
```

Compile userspace loader:

```bash
gcc user/loader.c -o user/loader -lbpf
```

Run:

```bash
sudo ./user/loader
```

## Requirements

- Linux kernel 5.x+
- clang
- libbpf
- root privileges

## Status

Working prototype.

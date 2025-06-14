#!/usr/bin/env python3

from bcc import BPF
from bcc.utils import printb
import sys

if len(sys.argv) < 2:
    print("Usage: {} <PID>".format(sys.argv[0]))
    exit(1)

pid_filter = int(sys.argv[1])

# Read and update the C code
with open("trace_open.c", "r") as f:
    bpf_program = f.read().replace("PID_FILTER", str(pid_filter))

b = BPF(text=bpf_program)
b.attach_kprobe(event="sys_enter_openat", fn_name="trace_syscall_openat")

# Callback for output
def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-6d %-16s %s" % (event.pid, event.comm, event.filename))

print("Tracing openat syscalls for PID {}...".format(pid_filter))
b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDetaching...")

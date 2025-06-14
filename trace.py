from bcc import BPF
import ctypes as ct

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    int flags;
};

BPF_PERF_OUTPUT(events);

int trace_openat(struct pt_regs *ctx) {
    struct data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Get filename argument
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), 
                        (void *)PT_REGS_PARM2(ctx));
    
    // Get flags argument
    data.flags = PT_REGS_PARM3(ctx);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="sys_openat", fn_name="trace_openat")

# Define output structure in Python
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("timestamp", ct.c_uint64),
        ("comm", ct.c_char * 16),
        ("fname", ct.c_char * 255),
        ("flags", ct.c_int)
    ]

# Process events
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print(f"PID: {event.pid} COMM: {event.comm.decode()} " +
          f"File: {event.fname.decode()} Flags: {event.flags:08x}")

# Loop and print events
b["events"].open_perf_buffer(print_event)
print("Tracing openat() calls... Ctrl+C to exit")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass
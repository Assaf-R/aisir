#include <linux/sched.h>  // For task_struct
#include <net/sock.h> // For socket struct

// This struct will be our main friend for this code and will hold every event that
// will trigger our ebpf prog, please note that not every event will fill all the 
// fields in the struct - That is on purpose
struct triggered_event {
    u64 event_time;
    char syscall_name[16];
    int pid;
    int ppid;
    int uid;
    char process_name[TASK_COMM_LEN];
    char parent_process_name[TASK_COMM_LEN];
    u32 target_ip;
};

BPF_ARRAY(ip_blacklist, u32, 256);

// This will make a perf buffer that will let me pass data back to the user mode handler
BPF_PERF_OUTPUT(output); 

static void enrich_data(void *ctx, struct triggered_event event)
{
    // All our syscall hook function will lead to this function, this function will add
    // agnostic data that will be a part of every event and send the final event
    // struct back to the user mode handler

    // What time is it?
    u64 now_time = bpf_ktime_get_ns();
    bpf_probe_read_kernel(&event.event_time, sizeof(now_time), &now_time);

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    struct task_struct *task;
    struct task_struct *parent_task;

    // Get the current task_struct
    task = (struct task_struct *)bpf_get_current_task();

    // Get the parent task_struct 
    parent_task = task->real_parent;
    bpf_probe_read_kernel_str(&event.parent_process_name, TASK_COMM_LEN, parent_task->comm);

    int ppid = parent_task->pid;
    bpf_probe_read_kernel(&event.ppid, (sizeof(ppid)), &ppid);

    // Get the child's process name
    bpf_get_current_comm(&event.process_name, TASK_COMM_LEN);

    u32 cur_ip = event.target_ip;
    if (cur_ip == 134744072) 
    {
        bpf_trace_printk("good ---- %d", cur_ip);
        bpf_override_return(ctx, -EACCES);
    }
    else
    {
        bpf_trace_printk("%d", cur_ip);
    }

    output.perf_submit(ctx, &event, sizeof(event)); 
}

int syscall__connect(struct pt_regs *ctx, int sockfd, const struct sockaddr *addr, int addrlen) 
{
    struct triggered_event event = {};
    char called_syscall[16] = "connect";   
    bpf_probe_read_kernel(&event.syscall_name, sizeof(event.syscall_name), called_syscall);
    
    u16 family;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    // Check its IPv4 socket
    if (family == AF_INET) 
    {
        struct sockaddr_in addr_in = {};
        bpf_probe_read_user(&addr_in, sizeof(addr_in), addr);
        event.target_ip = addr_in.sin_addr.s_addr;
    }
    
    enrich_data(ctx, event);

    return 0;
}

#include <linux/sched.h>  // For task_struct
#include <net/sock.h> // For socket struct

struct triggered_event {
    u64 event_time;
    char syscall_name[16];
    int pid;
    int ppid;
    int uid;
    char process_name[TASK_COMM_LEN];
    char parent_process_name[TASK_COMM_LEN];
    u32 target_ip;
    int blocked;
};

BPF_HASH(ip_blacklist, u32, u8);

BPF_PERF_OUTPUT(output); 

static int check_against_blacklist(u32 cur_ip) 
{
    u8 *found = ip_blacklist.lookup(&cur_ip);
    bpf_trace_printk("number: %d, %d", found, &found);

    return found ? 1 : 0; // 1 if found, 0 otherwise
}


static void enrich_data(void *ctx, struct triggered_event event)
{
    
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
    int res = check_against_blacklist(cur_ip);
    if(res) // If the ip is in the blacklist the result will be 1, else 0
    {
        bpf_probe_read_kernel(&event.blocked, (sizeof(res)), &res);
        bpf_override_return(ctx, -EACCES);
    }
    else
    {
        bpf_probe_read_kernel(&event.blocked, (sizeof(res)), &res);
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

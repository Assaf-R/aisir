from bcc import BPF
import socket, struct

EBPF_PROGRAM = "aisir_bpf.c"
IP_BLACKLIST = "ip_list.txt"

with open (EBPF_PROGRAM, 'r') as raw_program:
        program = raw_program.read()
b = BPF(text=program, cflags=["-Wno-macro-redefined"])

def junk(cpu):
    '''
    Sometimes when events aren't processed properly by the ebpf program or the buffer for the program isn't large enough
    event will be lost, instead of printing error message every time I rather disregard them.
    '''
    pass

def load_blacklist():
    with open(IP_BLACKLIST, 'r') as ip_list_file:
        ip_list = ip_list_file.read()
        for i in range(len(ip_list)):
            print(ip_list[i])
            b['ip_blacklist'][i] = struct.unpack('I', socket.inet_aton(ip_list[i]))[0]

def dict_events(data):
    '''
    In order to compare easily every event with every rule I want to have them both in the same format and because of
    the variety of the data I chose to use dict as my data format
    '''
    event = {
        "syscall": data.syscall_name.decode(),
        "pid": data.pid,
        "ppid": data.ppid,
        "uid": data.uid,
        "process_name": data.process_name.decode(),
        "parent_process_name": data.parent_process_name.decode(),
        "target_ip":socket.inet_ntoa(struct.pack('I', data.target_ip)),
        "raw_ip":data.target_ip
    }
    
    print(event)
   

def process_data(cpu, data, size):
    '''
    This function "connects" to the ebpf side and sends the data down the pipeline
    '''
    data = b["output"].event(data)
    dict_events(data)

def main():
    print("starting")


    s_connect = b.get_syscall_fnname("connect")

    b.attach_kprobe(event=s_connect, fn_name="syscall__connect")

    load_blacklist()

    buffer_size = 128 * 1024  # 128KB

    # This line "connects" the process_data function with checking the output buffer
    b["output"].open_perf_buffer(process_data, page_cnt=buffer_size // 4096, lost_cb=junk) 

    # I would like to always check the output
    while True:  
        try: 
            b.trace_print()
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main() 
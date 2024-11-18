
# aisir.py
# Ebpf based local firewall tool by Assaf R.
# --- --- ---

# Imports
from bcc import BPF
import socket, struct, ctypes

# Constants
EBPF_PROGRAM = "aisir_bpf.c"
IP_BLACKLIST = "ip_list.txt"
BUFFER_SIZE = 128 * 1024  # 128KB

# Load C program
with open (EBPF_PROGRAM, 'r') as raw_program:
        program = raw_program.read()
b = BPF(text=program, cflags=["-Wno-macro-redefined"])

def load_blacklist():
    '''
    Fill the hash table with our blacklisted IPs
    '''
    with open(IP_BLACKLIST, 'r') as ip_blacklist_file:
        ip_list = ip_blacklist_file.readlines()
        for ip in ip_list:
            print(f"Blacklist IP loaded - {ip}")
            b['ip_blacklist'][ctypes.c_uint(struct.unpack('I', socket.inet_aton(ip))[0])] = ctypes.c_int(1) # The 1 is for the c part
   

def process_data(cpu, data, size):
    '''
    converts data to dictionary and print it
    '''
    data = b["output"].event(data)
    event = {
        "syscall": data.syscall_name.decode(),
        "pid": data.pid,
        "ppid": data.ppid,
        "uid": data.uid,
        "process_name": data.process_name.decode(),
        "parent_process_name": data.parent_process_name.decode(),
        "target_ip":socket.inet_ntoa(struct.pack('I', data.target_ip)),
        "res":data.res
    }
    
    print(event)

def main():
    print("starting")

    s_connect = b.get_syscall_fnname("connect")

    b.attach_kprobe(event=s_connect, fn_name="syscall__connect")

    load_blacklist()

    b["output"].open_perf_buffer(process_data, page_cnt=BUFFER_SIZE // 4096) 
    
    while True:  
        try: 
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main() 

# aisir.py
# eBpf based local firewall tool by Assaf R.
# --- --- ---

# Imports
from bcc import BPF
import socket, struct, ctypes, os, time

# Constants
EBPF_PROGRAM = "aisir_bpf.c"
IP_BLACKLIST = "ip_list.txt"
BUFFER_SIZE = 128 * 1024  # 128KB
LOG_FOLDER = "/var/log/loch"
LOG_NAME = "aisir"
LOG_EXTENT = ".log"
LOG_MAX_SIZE = 8192

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
   

def logging(event):
    '''
    The log files called aisirX.log where X are incrementing numbers so every log file isn't too big.
    If the folder doesn't exist it creates it
    '''
    try:
        os.mkdir(LOG_FOLDER)
    except FileExistsError:
        pass

    log_number = 1
    last_log = False
    while not last_log:
        if os.path.isfile(f"{LOG_FOLDER}/{LOG_NAME}{log_number}{LOG_EXTENT}"):
            file_size = os.stat(f"{LOG_FOLDER}/{LOG_NAME}{log_number}{LOG_EXTENT}").st_size
            if file_size > LOG_MAX_SIZE:
                log_number += 1
            else:
                last_log = True
        else:
            last_log = True
    with open(f"{LOG_FOLDER}/{LOG_NAME}{log_number}{LOG_EXTENT}", 'a') as log_file:
        log_file.write(f"{event}\n") 

def format_events(event):

    msg = ""
    for key in event:
        msg += f"{key} - {event[key]}, "

    print(msg)

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
        "blocked":data.blocked
    }

    logging(format_events(event))

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
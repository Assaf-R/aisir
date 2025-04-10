# aisir.py
# eBpf based local firewall tool by Assaf R.
# --- --- ---

# Imports
from bcc import BPF
import socket, struct, ctypes, os, time, datetime, argparse

# Constants
EBPF_PROGRAM = "aisir_bpf.c"
IP_LIST = "ip_list.txt"
BUFFER_SIZE = 128 * 1024  # 128KB
LOG_FOLDER = "/var/log/loch"
LOG_NAME = "aisir"
LOG_EXTENT = ".log"
LOG_MAX_SIZE = 8192

# Globals
def load_bpf_prog():
    with open (EBPF_PROGRAM, 'r') as raw_program:
            program = raw_program.read()
    global b
    b = BPF(text=program, cflags=["-Wno-macro-redefined"])

boot_time = time.mktime(datetime.datetime.strptime(os.popen('uptime -s').read().strip(),"%Y-%m-%d %H:%M:%S").timetuple()) # The ebpf gives time since boot so I need this

def load_ip_list(filter_type):
    '''
    Fill the hash table with our blacklisted IPs
    '''

    b['filter_type'][0] = ctypes.c_int(filter_type) # 1 - Block : 0 - Pass

    if filter_type == 1:
        list_type = "Black"
    else:
        list_type = "White"

    with open(IP_LIST, 'r') as ip_list_file:
        ip_list = ip_list_file.readlines()
        for ip in ip_list:
            print(f"{list_type}list IP loaded - {ip}")
            b['ip_list'][ctypes.c_uint(struct.unpack('I', socket.inet_aton(ip))[0])] = ctypes.c_int(1) 

def what_time_is_it_right_now(ns_time):
    '''
    Adds time since boot to boot time
    '''
    global boot_time
    return(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(boot_time+(ns_time/1e9))))

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

    # If you want to debug uncomment next line 
    print(event)

    with open(f"{LOG_FOLDER}/{LOG_NAME}{log_number}{LOG_EXTENT}", 'a') as log_file:
        log_file.write(f"{event}\n") 

def format_events(event):

    msg = ""
    for key in event:
        msg += f"{key} - {event[key]}, "

    return(msg)

def process_data(cpu, data, size):
    '''
    converts data to dictionary and print it
    '''
    data = b["output"].event(data)
    event = {
        "event_time": what_time_is_it_right_now(data.event_time),
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

    parser = argparse.ArgumentParser(prog='aisir', description="ebpf based local firewall filter", epilog="choose either whitelist or blacklist")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-b', '--blacklist', action='store_true', help="Deny connection to IP addresses that are in the list")
    group.add_argument('-w', '--whitelist', action='store_true', help="Deny connection to IP addresses that aren't in the list")

    args = parser.parse_args()
    load_bpf_prog()

    if args.blacklist:
        print("aisir IP blacklist initialized")
        load_ip_list(1)
    elif args.whitelist:
        print("aisir IP whitelist initialized")
        load_ip_list(0)
    args = parser.parse_args()
    
    s_connect = b.get_syscall_fnname("connect")

    b.attach_kprobe(event=s_connect, fn_name="syscall__connect")


    b["output"].open_perf_buffer(process_data, page_cnt=BUFFER_SIZE // 4096) 
    
    while True:  
        try: 
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main() 
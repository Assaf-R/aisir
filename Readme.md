### Aisir
Named after the beautiful loch Aisir in northen Scotland, Aisir is an eBpf based tool that logs and filters connection to remote IP addresses

### How does this work?
The python program - aisir.py - loads the bpf c program - aisir_bpf.c - and hooks the connect syscall with a kprobe.
The eBpf program checks if a connection to the remote IP is allowed. in the ip_list.txt file.
The results are logged to /var/log/loch/aisirX.log

### How to run
***RUN AS ROOT***
You need to run the program with either the -w or -b flags, so your firewall wil work based on a whitelist or blacklist.
If you chose whitelist only connections to addresses in the list will be allowed, and if you chose blacklist they will be dropped

***notes***
- The ip_list.txt needs to be in the same dir with the programs
- The ip_list.txt file needs to include only valid ip addresses
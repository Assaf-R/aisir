### Aisir
Named after the beautiful loch Aisir in northen Scotland, Aisir is an eBpf based tool that logs and filters connection to remote IP addresses

### How does this work?
The python program - aisir.py - loads the bpf c program - aisir_bpf.c - and hooks the connect syscall with a kprobe.
The eBpf program checks if the remote IP is in the ip_list.txt file.
The results are logged to /var/log/loch/aisirX.log

***notes***
- The ip_list.txt needs to be in the same dir with the programs
- The ip_list.txt file needs to include only valid ip addresses
- ***RUN AS ROOT***
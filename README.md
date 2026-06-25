# decloaker

<p align="center">a simple tool to reveal files, directories and connections hidden by malware.</p>

<p align="center">
    <img width="250" height="250" alt="decloacker3" src="https://github.com/user-attachments/assets/6f052933-47fe-4784-b34c-3338e0b28fa0" /> 
</p>

<p align="center">•• <a href="#usage">Usage</a> • <a href="#malware-analysis-examples">Malware analysis examples</a> • <a href="https://github.com/gustavo-iniguez-goya/decloaker/releases">Downloads</a> • <a href="#todo">TODO</a> • <a href="#resources">Resources</a> ••</p>

### Usage

tl;dr: `./bin/decloaker --log-level detection scan system`

There're five main areas:

cat, list, move, delete or copy files without the libc.
  - Useful for LD_PRELOAD based rootkits. Use these commands instead of system `cp`, `rm`, `ls`, `mv`, `cat` or `stat` to manipulate files.

```bash
  cp [<orig> [<dest>]] [flags]

  rm <paths> ... [flags]

  ls [<paths> ...] [flags]

  mv [<orig> [<dest>]] [flags]

  cat [<paths> ...] [flags]

  stat [<paths> ...] [flags]
```

List, copy or get info of directories and files by accessing directly the disk device ([see the supported filesystems](https://github.com/gustavo-iniguez-goya/go-diskfs/tree/decloaker/filesystem)).

   - These options help to manipulate files or directories hidden by some kernel rootkits (like Diamorphine).
   - NOTE: only available for [some filesystems](https://github.com/gustavo-iniguez-goya/go-diskfs/tree/decloaker/filesystem).
   - NOTE: this feature does not work on tmpfs, so if /tmp is mounted on tmpfs, it won't find hidden files/directories.
     it'll work for LD_PRELOAD rootkits, and some kernel rootkits.

```bash
  disk ls --dev=STRING <paths> ... [flags]
    List directories and files by reading directly from the disk device

  disk cp --dev=STRING <orig> <dest> [flags]
    Copy directories and files directly from the disk device

  disk stat --dev=STRING <paths> ... [flags]
    Return information about a path

  disk cat --dev=STRING <path> [flags]
    Reads the content of a file and prints it to stdout
```

Scan the system to unhide files, directories, processes or kernel rootkits.

Use `--with-builtin-paths` to scan only hidden files or content predefined paths.
   
```bash
  scan hidden-files <paths> ... [flags]
    Look for hidden files, directories or processes (libc vs Go's std lib vs mmap).

  scan hidden-content <paths> ...
    Open a file and check if it has hidden content (libc vs Go's std lib vs mmap).

  scan hidden-lkms
    Look for hidden kernel modules.

  scan suspicious-procs [flags]
    Look for suspicious processes.

  scan hidden-procs
    Look for hidden processes.

  scan hidden-sockets [<protos> ...] [flags]
    Look for hidden sockets.

  scan system
    scan the system looking for hidden procs, lkms, files or content.
```

List sockets:

```bash
  netstat [<protos> ...] [flags]
    List connections from kernel via netlink.

  conntrack list
    Dump conntrack connections table from kernel.
```

Dump processes, opened files or kernel modules directly from the kernel, without parsing /proc/*:

```bash
  dump files [flags]
    Dump opened files.

  dump kmods
    Dump loaded kernel modules.

  dump tasks [flags]
    Dump running tasks (processes).
```

Example of listing running processes:

```bash
root@:~# /home/ga/decloaker dump tasks
Pid        PPid       Inode    UID    GID    Host         Comm             Exe
1          1          1703544  0      0      debian12-k3s systemd          /usr/lib/systemd/systemd
3276       3276       261966   65535  65535  kubeapps-internal-dashboard-69689f47dc-hp5fn pause            /pause
3539       3539       265011   65532  65532  coredns-697968c856-wmlnd coredns          /coredns
3598       3598       268220   1001   2001   dashboard-metrics-scraper-5bd45c9dd6-b7qgf metrics-sidecar  /metrics-sidecar
3738       3738       280114   1001   1001   kubeapps-internal-dashboard-69689f47dc-hp5fn nginx            /opt/bitnami/nginx/sbin/nginx
3879       3879       156554   100000 100000 lxc-grafana-debian12 "containerd-shim" "/usr/bin/containerd-shim-runc-v2"
3887       3887       4432     100000 100000 832106eef6ad "sh"             "/usr/bin/dash"
3949       3949       10162    100472 100000 44555dd7bb6b "sh"             "/bin/busybox"
3950       3950       27724    100000 100000 cd77355cd571 "entrypoint.sh"  "/usr/bin/bash"
4187       4187       11816    100472 100000 44555dd7bb6b "grafana"        "/usr/share/grafana/bin/grafana"
2715       2715       134508   100000 100000 lxc-jenkins "master"         "/usr/lib/postfix/sbin/master"
2716       2716       134505   100101 100110 lxc-jenkins "pickup"         "/usr/lib/postfix/sbin/pickup"
2717       2717       134503   100101 100110 lxc-jenkins "qmgr"           "/usr/lib/postfix/sbin/qmgr"
2731       2731       131106   100000 100000 lxc-jenkins "miniserv.pl"    "/usr/bin/perl"

```


### TODO

- [x] Read options from a configuration file.
- [ ] Display the differences when scanning with `scan hidden-content`.
- [x] Display what processes opened the existing sockets.
      - 1/2 done: does not work for connections opened in containers.

- [ ] Scan eBPF modules.

### Malware analysis examples

More analyses here: https://github.com/gustavo-iniguez-goya/decloaker/discussions/categories/malware-analysis

 - [Medusa rootkit](https://github.com/gustavo-iniguez-goya/decloaker/discussions/3)
 - [AUR malware campaign (11/06/2026)](https://github.com/gustavo-iniguez-goya/decloaker/discussions/4)

#### Father (LD_PRELOAD rootkit)

https://github.com/mav8557/Father

Revealing hidden content (this malware hides `/etc/ld.so.preload`):

```bash
root@localhost:~# echo /lib/selinux.so.3 > /etc/ld.so.preload
root@localhost:~# cat /etc/ld.so.preload
cat: /etc/ld.so.preload: No such file or directory
root@localhost:~#
```

As you see, l.so.preload apparently doesn't exist. Let's see what decloaker tells us:

```bash
root@localhost:~# /home/ga/decloaker scan hidden-content /etc/ld.so.preload
decloaker v0.0, pid: 763609

[i] Checking for hidden content /etc/ld.so.preload

=== CONTENT WARNING (read) /etc/ld.so.preload ===
cat content:
 
-----------------------------------------------------------------
Go read content:
 /lib/selinux.so.3

====================================
root@localhost:~#
```

Unmasking hidden files/directories (by default, anything with "lobster" in the name):

```bash
root@localhost:~# ls /home/ga/rootkits/ld_preload/Father/*lobster*
ls: cannot access '/home/ga/rootkits/ld_preload/Father/*lobster*': No such file or directory
root@localhost:~#
```

Using Go's standard lib (i.e.: using syscalls directly, without libc):

```bash
root@localhost:~# /home/ga/decloaker scan hidden-files --recursive /home/ga/rootkits/ld_preload/Father/
decloaker v0.0, pid: 764851

[i] Checking hidden files ["/home/ga/rootkits/ld_preload/Father/"]

drwxrwxr-x	4096	2025-09-25T10:07:57+01:00	/home/ga/rootkits/ld_preload/Father/.git/logs/refs/remotes
-rw-rw-r--	0	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster/file2.txt
[w] 	HIDDEN: /home/ga/rootkits/ld_preload/Father/lobster/file2.txt

(...)

HIDDEN dirs/files found:

	drwxrwxr-x	4096	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster
	-rw-rw-r--	0	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster/file0.txt
	-rw-rw-r--	0	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster/file1.txt
	-rw-rw-r--	0	2025-09-25T16:07:27+01:00	/home/ga/rootkits/ld_preload/Father/lobster_test1.txt
	-rw-rw-r--	0	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster/file2.txt
	-rw-rw-r--	0	2025-09-25T16:07:16+01:00	/home/ga/rootkits/ld_preload/Father/lobster/file3.txt

[i] use decloaker cp <orig> <dest> to backup the files, or decloaker rm <path> to delete them

root@localhost:~#
```

```bash
root@localhost:~# rm /etc/ld.so.preload
rm: cannot remove '/etc/ld.so.preload': No such file or directory
root@localhost:~# /home/ga/decloaker rm /etc/ld.so.preload
decloaker v0.0, pid: 765449

[i] Deleting files [/etc/ld.so.preload]
	/etc/ld.so.preload:	OK
root@locahost:~#
```

#### Diamorphine (kernel rootkit)

By default, it hides files or directories with "diamorphine_secret" in the name:

```bash
root@localhost:~# ls /home/ga/Diamorphine/
diamorphine.c	diamorphine.mod    diamorphine.o	   LICENSE.txt	  Module.symvers
diamorphine.h	diamorphine.mod.c  ***diamorphine_secret***	   Makefile	  README.md
diamorphine.ko	diamorphine.mod.o  ***diamorphine_secret.txt***  modules.order
root@localhost:~#
```

Load the rootkit, and verify that the files and directories with "diamorphine_secret" are gone:

```bash
root@localhost:~# insmod /home/ga/Diamorphine/diamorphine.ko 
```

```bash
root@localhost:~# ls /home/ga/Diamorphine/
diamorphine.c  diamorphine.ko	diamorphine.mod.c  diamorphine.o  Makefile	 Module.symvers
diamorphine.h  diamorphine.mod	diamorphine.mod.o  LICENSE.txt	  modules.order  README.md
root@localhost:~#
```

Try to list the files with decloaker `disk ls` tool:

```bash
root@localhost:~# /home/ga/decloaker --log-level detection disk ls -d /dev/sda1 /home/ga/Diamorphine/

HIDDEN dirs/files found:

	----------	0	2025-09-25T11:53:45+01:00	/home/ga/Diamorphine/diamorphine_secret.txt
	----------	4096	2025-09-25T11:53:51+01:00	/home/ga/Diamorphine/diamorphine_secret
	----------	0	2025-09-25T11:53:51+01:00	/home/ga/Diamorphine/diamorphine_secret/file_hidden.txt
root@localhost:~#
```

This rootkit can also hide processes, by sending them the signal `-31`:

```bash
root@localhost:~# sleep 99999 &
[1] 1203
root@localhost:~# sleep 99999 &
[1] 1204
root@localhost:~# pgrep sleep
1203
1204
root@localhost:~# kill -31 1203
root@localhost:~# kill -31 1204
root@localhost:~# pgrep -a sleep
root@localhost:~# 
root@localhost:~# ls /proc/|grep 1204
root@localhost:~# ls /proc/|grep 1203
root@localhost:~#
```

Let's try to unhide these processes:

```bash
root@localhost:~# /home/ga/decloaker scan hidden-procs
[i] Checking hidden processes:

dr-xr-xr-x	0	2025-10-12T19:07:20+01:00	/proc/1
(...)
dr-xr-xr-x	0	2025-10-12T19:07:20+01:00	/proc/17

[i] 	files checked (151/150)
[i] 	no hidden dirs/files found

WARNING (ebpf): pid hidden?
	PID: 1203	PPid: 1203
	Inode: 946157	Uid: 0	Gid: 0
	Comm: "sleep"
	Path: ""

	PID confirmed via Stat: 1203, "sleep"

[i] Stat /proc/1203:
dr-xr-xr-x	0	2025-10-12T19:07:48+01:00	1203

	Size: 0 	Block size: 1024 	Blocks: 0
	Device: 21 	Rdev: 0 	Inode: 20865 	Links: 9
	UID: 0 GID: 0
	Access: 2025-10-12 19:07:48.916 +0100 BST
	Modify: 2025-10-12 19:07:48.916 +0100 BST
	Change: 2025-10-12 19:07:48.916 +0100 BST


WARNING (ebpf): pid hidden?
	PID: 1204	PPid: 1204
	Inode: 946157	Uid: 0	Gid: 0
	Comm: "sleep"
	Path: ""

	PID confirmed via Stat: 1204, "sleep"

[i] Stat /proc/1204:
dr-xr-xr-x	0	2025-10-12T19:07:49+01:00	1204

	Size: 0 	Block size: 1024 	Blocks: 0
	Device: 21 	Rdev: 0 	Inode: 20872 	Links: 9
	UID: 0 GID: 0
	Access: 2025-10-12 19:07:49.828 +0100 BST
	Modify: 2025-10-12 19:07:49.828 +0100 BST
	Change: 2025-10-12 19:07:49.828 +0100 BST


[w] hidden processes found.


root@localhost:~#
```

Some notes regarding this output:

 - Some kernel rootkits just hide the enumeration of /proc/* (ls /proc/).
 - If you list the path (ls /proc/1204/) you can list the files and read them.
 - You can also use cd to confirm that the path exists.
 - Some kernel rootkits prevent all of this, but sometimes `stat` still works, so that's why the message "PID confirmed via Stat" appears.

This rootkit also hides itself from the system:

```bash
root@localhost:~# grep diamorphine /proc/modules
root@localhost:~#
```

See if we can reveal it:

```bash
root@localhost:~# /home/ga/decloaker scan hidden-lkms
decloaker v0.0, pid: 763715

[i] Checking kernel integrity
WARNING: kernel tainted
	(E) unsigned module loaded on a kernel that supports module signatures
	(O) externally-built ('out-of-tree') module was loaded


[i] Checking loaded kernel modules
tainted: d diamorphine/, OE

	WARNING: "diamorphine" kmod HIDDEN from /proc/modules

root@localhost:~# 
```

You can also use `decloaker disk --dev=/dev/sda1 cp /path/to/hidden_file.txt hidden_file_backup.txt`.

Note:

Some rootkits have the ability to hide patterns to the standard output:
 
```bash
root@localhost:~# /home/ga/decloaker disk find -d /dev/sda1 / -c --log-level=detection
HIDDEN: /           _blackhole/test.txt
HIDDEN: /           _blackhole/aa
HIDDEN: /mnt/      /
HIDDEN: /mnt/      /
HIDDEN: /mnt/      /
HIDDEN: /mnt/      /
```

Regular tools like ls, mv or cp won't work on these files, but with decloaker even though you can't actuate individually on each file,
you can copy the directory recursively to a network shared directory or an external storage, and inspect it from another computer:

```bash
root@localhost:~# ls /mnt
root@localhost:~# /home/ga/decloaker disk cp -d /dev/sda1 -r /mnt /mnt/pc1/
root@localhost:~#

ga@pc1:~# ls /mnt/shared/
secret
ga@pc1:~# ls /mnt/shared/secret/
secret.xt secret2.txt secret3.txt
```

--

### Resources

 - [User-space library rootkits revisited: Are user-space detection mechanisms futile?](https://arxiv.org/html/2506.07827v1)
 - [The Hidden Threat: Analysis of Linux Rootkit Techniques and Limitations of Current Detection Tools](https://dl.acm.org/doi/10.1145/3688808)
 - [Linux rootkits explained – Part 1: Dynamic linker hijacking](https://www.wiz.io/blog/linux-rootkits-explained-part-1-dynamic-linker-hijacking)
 - [Linux rootkits explained – Part 2: Loadable kernel modules](https://www.wiz.io/blog/linux-rootkits-explained-part-2-loadable-kernel-modules#detecting-lkm-rootkits-85)
 - [In-Depth Study of Linux Rootkits: Evolution, Detection, and Defense](https://www.first.org/resources/papers/amsterdam25/FIRST_Amsterdam_2025_Linux_Rootkits.pdf)
 - [Sandfly Security's articles on Linux forensics and malware](https://sandflysecurity.com/blog/tag/linux-forensics)
 - [Hiding Linux Processes with Bind Mounts](https://righteousit.com/2024/07/24/hiding-linux-processes-with-bind-mounts/)
 - [How to detect a LD_PRELOAD rootkit and hide from ldd & /proc](https://matheuzsecurity.github.io/hacking/ldpreload-rootkit/)
 - [How is /proc able to list process IDs](https://ops.tips/blog/how-is-proc-able-to-list-pids/)

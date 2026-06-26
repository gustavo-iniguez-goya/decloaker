#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

volatile __u32 pid = 0;
volatile __u32 ppid = 0;

char path[1024]={0};
char exe_path[1024]={0};
unsigned long inode=0;
uid_t uid = 0;
gid_t gid = 0;

void get_exe_info(struct mm_struct *mm){
    if (!mm){
        return;
    }
    struct file *exe = mm->exe_file;
    if (!exe)
        return;
    struct inode *ino = exe->f_inode;
    if (ino){
        inode = ino->i_ino;
    }

    // XXX: kernels 5.x "helper call is not allowed in probe"
    bpf_d_path(&exe->f_path, exe_path, 1024);
}

SEC("iter/task_file")
int dump_files(struct bpf_iter__task_file *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    struct file *file = ctx->file;
    __u32 fd = ctx->fd;

    if (task == (void *)0 || file == (void *)0)
        return 0;

    if (pid > 0 && task->pid != (pid_t)pid){
        return 0;
    }
    pid_t _ppid = 0;
    bpf_probe_read_kernel(&_ppid, sizeof(_ppid), &task->real_parent->pid);
    if (ppid > 0 && _ppid != (pid_t)ppid){
        return 0;
    }


    if (ctx->meta->seq_num == 0) {
        BPF_SEQ_PRINTF(seq, "    pid      tgid       fd      inode      file      exe\n");
    }
    const struct cred *creds = task->cred;
    if (creds){
        uid = creds->uid.val;
        gid = creds->gid.val;
    }
    get_exe_info(task->mm);

    char comm[TASK_COMM_LEN]={0};
    BPF_CORE_READ_STR_INTO(&comm, task, comm);
    bpf_d_path(&file->f_path, path, 1024);

#pragma unroll
    for (int i = 0; i < sizeof(comm); i++) {
        if (comm[i] == '\n') {
            comm[i] = '_';
        }
    }
#pragma unroll
    for (int i = 0; i < sizeof(path); i++) {
        if (path[i] == '\n') {
            path[i] = '_';
        }
    }

    BPF_SEQ_PRINTF(seq, "pid=%d ppid=%d fd=%d inode=%d uid=%d gid=%d host=%s file=%s comm=%s exe=%s\n",
            task->pid,
            _ppid,
            fd,
            file->f_inode->i_ino,
            uid,
            gid,
            task->nsproxy->uts_ns->name.nodename,
            path,
            comm,
            exe_path);
    __builtin_memset(&path, 0, sizeof(path));
    __builtin_memset(&exe_path, 0, sizeof(exe_path));
    inode=0;
    return 0;
}

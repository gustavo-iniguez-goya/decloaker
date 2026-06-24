#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

volatile __u32 pid = 0;
volatile __u32 ppid = 0;

char path[1024]={0};
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
#ifdef WITH_PATH
    bpf_d_path(&exe->f_path, path, 1024);
#endif
}

SEC("iter/task")
int dump_tasks(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (seq == NULL){
        return 0;
    }
    if (!task){
        return 0;
    }

	if (pid > 0 && task->pid != (pid_t)pid) {
		return 0;
	}
	if (ppid > 0 && task->tgid != (pid_t)ppid) {
		return 0;
	}

    const struct cred *creds = task->cred;
    if (creds){
        uid = creds->uid.val;
        gid = creds->gid.val;
    }
    get_exe_info(task->mm);

    pid_t pid = task->pid;
    pid_t ppid = task->tgid;
    char comm[TASK_COMM_LEN]={0};
    BPF_CORE_READ_STR_INTO(&comm, task, comm);

    // replace \n characters, to avoid conflicts with bpf_seq_printf()
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

    BPF_SEQ_PRINTF(seq, "pid=%d ppid=%d inode=%d uid=%d gid=%d host=%s comm=%s exe=%s\n",
            pid, ppid,
            inode,
            uid,
            gid,
            task->nsproxy->uts_ns->name.nodename,
            comm,
            path);

    __builtin_memset(&path, 0, sizeof(path));
    inode=0;
    return 0;
}

char _license[] SEC("license") = "GPL";

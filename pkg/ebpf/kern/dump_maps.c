//
// https://elixir.bootlin.com/linux/v6.17.8/source/tools/testing/selftests/bpf/progs/bpf_iter_task_vmas.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


/* Copied from mm.h */
#define VM_READ		0x00000001
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_MAYSHARE	0x00000080

/* Copied from kdev_t.h */
#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)
#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))

#define D_PATH_BUF_SIZE 1024
char d_path_buf[D_PATH_BUF_SIZE] = {};
volatile __u32 pid = 0;
volatile __u32 ppid = 0;

SEC("iter/task_vma") int dump_maps(struct bpf_iter__task_vma *ctx)
{
	struct vm_area_struct *vma = ctx->vma;
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file;
	char perm_str[] = "----";

	if (task == (void *)0)
		return 0;

	if (pid > 0 && task->pid != (pid_t)pid) {
		return 0;
	}
	if (ppid > 0 && task->tgid != (pid_t)ppid) {
		return 0;
	}
    pid_t _pid = task->pid;
    pid_t _ppid = task->tgid;
    char comm[TASK_COMM_LEN]={0};
    BPF_CORE_READ_STR_INTO(&comm, task, comm);

    // XXX: allow to filter by perms?
    if (vma == (void *)0){
	    BPF_SEQ_PRINTF(seq, "vm_start=0 vm_end=0 perms=%s ", perm_str);
    } else {
        file = vma->vm_file;
        perm_str[0] = (vma->vm_flags & VM_READ) ? 'r' : '-';
        perm_str[1] = (vma->vm_flags & VM_WRITE) ? 'w' : '-';
        perm_str[2] = (vma->vm_flags & VM_EXEC) ? 'x' : '-';
        perm_str[3] = (vma->vm_flags & VM_MAYSHARE) ? 's' : 'p';
        BPF_SEQ_PRINTF(seq, "vm_start=%08llx vm_end=%08llx perms=%s ", vma->vm_start, vma->vm_end, perm_str);
    }

	if (file) {
		__u32 dev = file->f_inode->i_sb->s_dev;

//#ifdef WITH_PATH
		bpf_d_path(&file->f_path, d_path_buf, D_PATH_BUF_SIZE);
//#endif

		BPF_SEQ_PRINTF(seq, "offset=%08llx ", vma->vm_pgoff << 12);
		BPF_SEQ_PRINTF(seq, "dev=%02x:%02x inode=%u file=%s ", MAJOR(dev), MINOR(dev), file->f_inode->i_ino, d_path_buf);
		BPF_SEQ_PRINTF(seq, "pid=%d ppid=%d comm=%s path=\n", _pid, _ppid, comm);
	} else {
		BPF_SEQ_PRINTF(seq, "%08llx dev=00:00 inode=0 file= pid=%d ppid=%d comm=%s path=\n", 0ULL, _pid, _ppid, comm);
	}
	return 0;
}


char _license[] SEC("license") = "GPL";

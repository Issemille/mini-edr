#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>



struct event {
	__u32 pid;
	__u32 uid;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");


SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid & 0xFFFFFFFF;

	
	if (uid != 1000)
		return 0;
	

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if(!e)
		return 0;

	e->pid = pid;
	e->uid = uid;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));


	bpf_ringbuf_submit(e, 0);

	return 0;

}

char LICENSE[] SEC("license") = "GPL";

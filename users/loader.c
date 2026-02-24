#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>


static FILE *out;


struct event {
	__u32 pid;
	__u32 uid;
	char comm[16];
};

int handle_event(void *ctx, void *data, size_t len)
{
	struct event *e = data;
	time_t now= time(NULL);
	fprintf(out, "%ld,%u,%u,%s\n", (long)now, e->pid, e->uid, e->comm);
	fflush(out);
	printf("PID: %u UID: %u COMM: %s\n", e->pid, e->uid, e->comm);
	return 0;
}






int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open_file("../ebpf/exec.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_exec");
    if (!prog) {
        fprintf(stderr, "Failed to find program\n");
        return 1;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach program\n");
        return 1;
    }

    printf("eBPF program loaded and attached. Press Ctrl+C to exit.\n");





    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if(map_fd<0){
        fprintf(stderr, "Failed to find events map \n");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if(!rb){
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }





    out= fopen("events.csv", "a");
    if(!out){
	    perror("fopen");
	    return 1;
	}

    fprintf(out, "ts,pid,uid,comm\n");
    fflush(out);






    while (1) {
	    int err = ring_buffer__poll(rb, 100);
	    if(err<0){
		    fprintf(stderr, "poll error: %d\n", err);
		    break;
		   }
	    }


    return 0;
}

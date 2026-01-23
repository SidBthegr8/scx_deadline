#include <iostream>
#include <vector>
#include <cstring>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

struct task_rel_dl {
	struct bpf_spin_lock lock;
	uint64_t	rel_deadline;
};

#define MAP_PIN_PATH "/sys/fs/bpf/tsk_rel_dl"

uint64_t get_rel_deadline(int tid)
{
    int map_fd = bpf_obj_get(MAP_PIN_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 2;
    }

    struct task_rel_dl rel_dl_struct;
    memset(&rel_dl_struct, 0, sizeof(rel_dl_struct));
    int ret = bpf_map_lookup_elem(map_fd, &tid, &rel_dl_struct);
    close(map_fd);
    if (ret != 0) {
        std::cout << "TID " << tid << ": not found or error (errno=" << errno << ")" << std::endl;
        return -1;
    }
    return rel_dl_struct.rel_deadline;
}

void set_rel_deadline(int tid, uint64_t rel_dl)
{
    int map_fd = bpf_obj_get(MAP_PIN_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return;
    }

    struct task_rel_dl rel_dl_struct;
    memset(&rel_dl_struct, 0, sizeof(rel_dl_struct));
    rel_dl_struct.rel_deadline = rel_dl;
    //int ret = bpf_map_lookup_elem(map_fd, &tid, &rel_dl_struct);
    int ret = bpf_map_update_elem(map_fd, &tid, &rel_dl_struct, BPF_ANY|BPF_F_LOCK);
    close(map_fd);
    if (ret != 0) {
        std::cout << "TID " << tid << ": not found or error (errno=" << errno << ")" << std::endl;
    }
}
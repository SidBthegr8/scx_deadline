#include <math.h>
#define BPF_NO_KFUNC_PROTOTYPES
// #include <asm-generic/errno-base.h>
#include <scx/common.bpf.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define BPF_ASSERT(cond) \
    do { \
        if (!(cond)) \
            scx_bpf_error("Error: " #cond " was false"); \
    } while (0)

UEI_DEFINE(uei);

#define NS_IN_SEC 1000000000ULL
#define FALLBACK_DSQ_ID 0

#define NUM_BUCKETS 100
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define NR_L0 DIV_ROUND_UP(NUM_BUCKETS, 64)
#define NR_L1 (NR_L0 > 1 ? DIV_ROUND_UP(NR_L0, 64) : 0)
#define NR_L2 (NR_L1 > 1 ? DIV_ROUND_UP(NR_L1, 64) : 0)
#define NR_L3 (NR_L2 > 1 ? DIV_ROUND_UP(NR_L2, 64) : 0)
#define MAX_BITMASK_U64S (NR_L0 + NR_L1 + NR_L2 + NR_L3)
#define NUM_LEVELS ((NR_L0 > 0) + (NR_L1 > 0) + (NR_L2 > 0) + (NR_L3 > 0))
#define L0_OFF 0
#define L1_OFF (L0_OFF + NR_L0)
#define L2_OFF (L1_OFF + NR_L1)
#define L3_OFF (L2_OFF + NR_L2)

static inline int get_level_offset(int level){
	switch(level){
		case 0:
			return L0_OFF;
		case 1:
			return L1_OFF;
		case 2:
			return L2_OFF;
		case 3:
			return L3_OFF;
		default:
			bpf_printk("[get_level_offset] wrong level queried!!!");
			return -1;
	}
}

struct bucket_bitmask_data{
	struct bpf_spin_lock lock;
	int sem;
	u64 bitmasks[MAX_BITMASK_U64S];
};

struct{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct bucket_bitmask_data);
} bucket_bitmask_map SEC(".maps");

static inline void set_bitmask_tree(struct bucket_bitmask_data *b_data,
					     u64 bucket_idx)
{
	u64 curr_idx = bucket_idx / 64;
	u64 bit = bucket_idx % 64;
	// bpf_printk("[set_bitmask_tree] bucket_idx: %d", bucket_idx);
	#pragma unroll
	for (int l = 0; l < 4; l++) {
		if (l >= NUM_LEVELS)
			break;

		int offset = get_level_offset(l);
		int final_idx = offset + curr_idx;
		if(final_idx >= MAX_BITMASK_U64S || final_idx<0) {break;}
		u64 old_val =
					b_data->bitmasks[final_idx];
		b_data->bitmasks[final_idx] |= (1ULL << bit);
		// bpf_printk(
		// 	"[set_bitmask_tree] final_idx: %d, b_data->bitmasks[final_idx]:0x%llx",
		// 	final_idx,
		// 	b_data->bitmasks[final_idx]);
			 
		if (old_val != 0) {break;}

		bit = curr_idx % 64;
		curr_idx /= 64;
	}
}

static inline void
clear_bitmask_tree(struct bucket_bitmask_data *b_data, u64 bucket_idx)
{
	u64 curr_idx = bucket_idx / 64;
	u64 bit = bucket_idx % 64;
	// bpf_printk("[clear_bitmask_tree] bucket_idx: %d", bucket_idx);
	#pragma unroll
	for (int l = 0; l < 4; l++) {
		if (l >= NUM_LEVELS)
			break;

		int offset = get_level_offset(l);
		int final_idx = offset + curr_idx;
		if (final_idx >= MAX_BITMASK_U64S || final_idx < 0) {
			break;
		}
		b_data->bitmasks[final_idx] &= ~(1ULL << bit);
		// bpf_printk(
		// 	"[clear_bitmask_tree] final_idx: %d, b_data->bitmasks[final_idx]:0x%llx",
		// 	final_idx, b_data->bitmasks[final_idx]);
		if (b_data->bitmasks[final_idx] != 0)
			break;
		bit = curr_idx % 64;
		curr_idx /= 64;
	}
}

static inline u64
get_highest_bitmask_tree(struct bucket_bitmask_data *b_data)
{
	u64 curr_idx = 0;
	int root_level = NUM_LEVELS - 1;
	// bpf_printk("[get_highest_bitmask_tree] curr_idx: %d, root_level: %d", curr_idx, root_level);
	#pragma unroll
	for (int l = 3; l >= 0; l--) {
		if (l > root_level)
			continue;

		int offset = get_level_offset(l);
		u64 final_idx = offset + curr_idx;
		if (final_idx >= MAX_BITMASK_U64S || final_idx<0) {
			return ~0ULL; // or break/return depending on the function
		}
		u64 val = b_data->bitmasks[final_idx];
		if (val == 0)
			return -1;

		int highest_bit = 63 - __builtin_clzll(val);
		if (l == 0)
			return ((curr_idx * 64) + highest_bit);

		curr_idx = (curr_idx * 64) + highest_bit;
		// bpf_printk(
		// 	 "[get_highest_bitmask_tree] curr_idx: %d, b_data->bitmasks[offset + curr_idx]: 0x%llx",
		// 	curr_idx, b_data->bitmasks[offset + curr_idx]);
	}
	return -1;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 100); /* number of pages */
#ifdef __TARGET_ARCH_arm64
    __ulong(map_extra, 0x1ull << 32); /* start of mmap() region */
#else
    __ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
#endif
} arena SEC(".maps");


#include "bpf_arena_alloc.h"
#include "bpf_arena_list.h"

static int inited;
static bool scx_arena_verify_once;
// static u64 __arena * bucket_bitmask_array;

__hidden void scx_arena_subprog_init(void)
{
	if (scx_arena_verify_once)
		return;

	bpf_printk("%s: arena pointer %p", __func__, &arena);
	scx_arena_verify_once = true;
}

struct arena_list_head __arena* list_head;
struct arena_list_head __arena global_head;

struct arena_task_node {
	struct arena_list_node node;
	int pid;
	u64 cpumask;
	u64 bucket;
	bool in_bucket;
};

struct task_ctx {
	struct bpf_spin_lock lock;
	struct arena_task_node __arena* atnode;
	u64	abs_deadline;
	bool valid;
	int pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct deadline_wheel_slot {
	struct bpf_spin_lock lock;
	struct arena_list_head __arena* head_ptr;
	int bucket_count;
	int sem;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct deadline_wheel_slot);
	__uint(max_entries, NUM_BUCKETS);
} dl_wheel SEC(".maps");

struct cpu_curr_task {
	struct bpf_spin_lock lock;
	bool valid;
	int curr_pid;
	u64 curr_abs_dl;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, struct cpu_curr_task);
} cpu_curr_task_map SEC(".maps");

struct task_rel_dl {
	struct bpf_spin_lock lock;
	u64	rel_deadline;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, struct task_rel_dl);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} task_relative_deadlines_map SEC(".maps");

static void print_bucket_list(u64 bucket_idx, struct deadline_wheel_slot* bucket)
{
	struct arena_task_node __arena * atnode = NULL;
	bpf_printk("Bucket %llu (count=%d)", bucket_idx, bucket->bucket_count);
	list_for_each_entry(atnode, bucket->head_ptr, node)
	{
		bpf_printk("%d->", atnode->pid);
	}
}


// static inline int get_highest_bit(u64 val)
// {
// 	if (val == 0)
// 		return -1;
// 	return 63 - __builtin_clzll(val);
// }

enum {
	MS_TO_NS		= 1000LLU * 1000,
	TIMER_INTERVAL_NS	= (100 * MS_TO_NS),
};

struct central_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct central_timer);
} central_timer SEC(".maps");

s32 BPF_STRUCT_OPS_SLEEPABLE(deadline_wheel_init)
{
	int ret = scx_bpf_create_dsq(FALLBACK_DSQ_ID, -1);
	if (ret)
		return ret;

	s32 cpu;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) 
	{
		struct cpu_curr_task curr_task;
		curr_task.valid = false;
		curr_task.curr_pid = -1;
		curr_task.curr_abs_dl = 0x7FFFFFFFFFFFFFFFULL;
		int res = bpf_map_update_elem(&cpu_curr_task_map, &cpu, &curr_task, BPF_ANY|BPF_F_LOCK);
		if (res)
		{
			scx_bpf_error("Failed to initialize cpu_curr_task_map for cpu %d", cpu);
			return -ENOMEM;
		}
		// bpf_printk("[DEBUG] [INIT] Initialized running_task_ctx[cpu %d]", cpu);
	}

	for (u64 i = 0; i < NUM_BUCKETS; i++)
	{
		struct deadline_wheel_slot new_dl_slot;
		new_dl_slot.head_ptr = bpf_alloc(sizeof(*(new_dl_slot.head_ptr)));
		// new_dl_slot.head_ptr->first = NULL;
		new_dl_slot.bucket_count = 0;
		new_dl_slot.sem = 0;
		int res = bpf_map_update_elem(&dl_wheel, &i, &new_dl_slot, BPF_ANY|BPF_F_LOCK);
		if (res != 0)
		{
			scx_bpf_error("Error. Failed to initialize deadline wheel slot %llu.", i);
			return -1;
		}
		// bpf_printk("[INFO] [INIT] Initialized deadline wheel slot # %llu.\n", i);
	}

	// bucket_bitmask_array = NULL;
	// // Create as many u64s needed to represent each bucket with a bit
	// int num_bitfields = ceil((double)NUM_BUCKETS / (double)64);
	// bucket_bitmask_array = bpf_alloc(sizeof(u64) * num_bitfields);
	// if (bucket_bitmask_array == NULL)
	// {
	// 	scx_bpf_error("Failed to allocate bitmask array");
	// 	return -1;
	// }
	// bpf_printk("Allocated bitmask array with %d u64s\n", num_bitfields);
	// for (int i = 0; i < num_bitfields; i++)
	// {
	// 	bucket_bitmask_array[i] = (u64)0;
	// }

	u32 key = 0;
	struct bucket_bitmask_data *b_data =
		bpf_map_lookup_elem(&bucket_bitmask_map, &key);
	if (!b_data) {
		scx_bpf_error("Failed to lookup bucket_bitmask_map");
		return -1;
	}

	bpf_spin_lock(&b_data->lock);
	#pragma unroll
	for (int i = 0; i < MAX_BITMASK_U64S; i++) {
		b_data->bitmasks[i] = 0;
	}
	bpf_spin_unlock(&b_data->lock);

	__sync_fetch_and_add(&inited, 1);

	bpf_printk("[INFO] [INIT] Initialized SCX Deadline Wheel Scheduler with %d cpus and %llu bucket slots", scx_bpf_nr_cpu_ids(), NUM_BUCKETS);
	return 0;
}

static int clear_task_deadlines(struct bpf_map *map, void *key, void *value, void *ctx)
{
	bpf_map_delete_elem(map, key);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(deadline_wheel_exit, struct scx_exit_info *ei)
{
	// bpf_free(bucket_bitmask_array);
	// bpf_for_each_map_elem(&task_relative_deadlines_map, clear_task_deadlines, NULL, 0);
	bpf_printk("[INFO] [EXIT] Exiting SCX Deadline Wheel Scheduler\n");
	UEI_RECORD(uei, ei);
	return 0;
}

static u64 get_rel_deadline(struct task_struct *p)
{
	struct task_rel_dl* existing_rel_dl;
	int pid = p->pid;
	existing_rel_dl = bpf_map_lookup_elem(&task_relative_deadlines_map, &pid);
	if (existing_rel_dl)
	{
		bpf_printk("[DEBUG] [HELPER] Found existing rel dl for pid %d: %llu\n", pid, existing_rel_dl->rel_deadline);
		return existing_rel_dl->rel_deadline;
	}

	// struct task_rel_dl new_rel_dl;
	// new_rel_dl.rel_deadline = NS_IN_SEC;
	struct task_rel_dl new_rel_dl = { .rel_deadline = NS_IN_SEC };
	int res = bpf_map_update_elem(&task_relative_deadlines_map, &pid, &new_rel_dl, BPF_ANY|BPF_F_LOCK);
	if (res)
	{
		scx_bpf_error("tsk_rel_dl update failed for pid %d", pid);
		return -ENOMEM;
	}
	bpf_printk("[DEBUG] [HELPER] Did not find an existing relative deadline for pid %d. Set new one to: %llu\n", pid, new_rel_dl.rel_deadline);
	return NS_IN_SEC;
}

void BPF_STRUCT_OPS(deadline_wheel_enable, struct task_struct *p)
{
	scx_arena_subprog_init();
	u64 rel_dl = get_rel_deadline(p);
	bpf_printk("[DEBUG] [ENABLE] Enabling task %d with relative deadline %llu\n", p->pid, rel_dl);
	u64 abs_deadline = scx_bpf_now() + rel_dl;

	// Create a new task context structure for this thread
	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE))) {
		scx_bpf_error("Failed to allocate task_ctx for pid %d", p->pid);
		return;
	}

	// Allocate a new arena linked list node for this thread
	struct arena_task_node __arena* new_atnode = bpf_alloc(sizeof(*new_atnode));
	if (new_atnode == NULL)
	{
		scx_bpf_error("Failed to allocate new node for pid %d", p->pid);
		return;
	}
	bpf_printk("Allocated node for pid %d at address 0x%x\n", p->pid, new_atnode);
	
	new_atnode->pid = p->pid;
	new_atnode->cpumask = 0;
	new_atnode->in_bucket = false;

	// Set the context parameters
	bpf_spin_lock(&tctx->lock);
	tctx->atnode = new_atnode;
	tctx->abs_deadline = abs_deadline;
	tctx->pid = p->pid;
	tctx->valid = true;
	tctx->atnode->cpumask = (u64)*(int*)p->cpus_ptr;
	bpf_spin_unlock(&tctx->lock);
	bpf_printk("[INFO] [ENABLE] Set task %d mask to 0x%x\n.", p->pid, tctx->atnode->cpumask);

	struct arena_task_node __arena* atnode_addr = tctx->atnode;
	struct arena_list_node __arena* list_node_addr = NULL;
	if (tctx->atnode) list_node_addr = &(tctx->atnode->node);

	u64 time_from_now_us = (abs_deadline - scx_bpf_now())/1000ULL;
	bpf_printk("[DEBUG] [ENABLE] Task %d (%s) policy=%u, mask=%x, node = 0x%x, atnode = 0x%x\n", 
		p->pid, p->comm, p->policy, *(int*)(p->cpus_ptr), list_node_addr, atnode_addr);
}

struct slock_ctx {
	int *val;
	bool got_lock;
};

static inline long slock_work(u32 index, void *ctx){
	struct slock_ctx *lctx = ctx;
	/* Return 1 to stop looping (we got the lock) */
	/* Return 0 to continue looping */
	if (__sync_val_compare_and_swap(lctx->val, 0, 1) == 0)
	{
		lctx->got_lock = true;
		return 1;
	}
	for(int temp=0; temp<100000; temp++){}
	return 0;
}

static void slock(int* val){	
	struct slock_ctx lctx = { .val = val, .got_lock = false};

	bpf_loop(100000, slock_work, &lctx, 0);
	if(!lctx.got_lock){
		scx_bpf_error("[SLOCK] Couldn't get lock!!!");
	}
}

void BPF_STRUCT_OPS(deadline_wheel_disable, struct task_struct *p)
{
	scx_arena_subprog_init();
	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, 0))) {
		scx_bpf_error("task_ctx lookup/creation failed");
		return;
	}

	bpf_spin_lock(&tctx->lock);
	tctx->valid = false;
	tctx->abs_deadline = 0x7FFFFFFFFFFFFFFFULL;
	bpf_spin_unlock(&tctx->lock);

	if (tctx->atnode->in_bucket)
	{
		u64 bucket_idx = tctx->atnode->bucket;
		struct deadline_wheel_slot* bucket;
		if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
			scx_bpf_error("Failed to get bucket idx %llu pointer, after creating it", bucket_idx);
			return;
		}

		// bpf_spin_lock(&bucket->lock);
		slock(&bucket->sem);
		bpf_printk("[DISABLE] Got bucket->sem!!");
		if (tctx->atnode && tctx->atnode->in_bucket)
		{
			list_del(&tctx->atnode->node);
			tctx->atnode->in_bucket = false;
			bucket->bucket_count--;
		}
		// bpf_spin_unlock(&bucket->lock);
		__sync_val_compare_and_swap(&bucket->sem, 1, 0);
		
		bpf_printk("[INFO] [DISABLE] Removed pid %d from bucket %llu. %d tasks remain in bucket\n", p->pid, bucket_idx, bucket->bucket_count);
		print_bucket_list(bucket_idx, bucket);
		if (bucket->bucket_count < 0)
		{
			scx_bpf_error("[ERROR] [DISABLE] Number of tasks in bucket %llu is %d\n", bucket_idx, bucket->bucket_count);
		}
	}

    bpf_free(tctx->atnode);
	tctx->atnode = NULL;

	bpf_printk("[INFO] [DISABLE] Task %d (%s) disabled\n", p->pid, p->comm);
}

s32 BPF_STRUCT_OPS(deadline_wheel_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bpf_printk("[DEBUG] [SELECT_CPU] Skipping select_cpu for task %d (%s)\n", p->pid, p->comm);
	return prev_cpu;
}

static struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *tctx;

	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0))) {
		scx_bpf_error("task_ctx lookup failed");
		return NULL;
	}
	return tctx;
}

static s32 find_idle_cpu(struct task_struct *p, s32 prev_cpu)
{

	// First check if the previous cpu the task ran on is now available. This can help avoid migration
	u32 key;
	bool prev_cpu_idle = scx_bpf_test_and_clear_cpu_idle(prev_cpu);
	if(prev_cpu_idle)
	{
		key = prev_cpu;
		struct cpu_curr_task* cpu_curr_task_ctx = bpf_map_lookup_elem(&cpu_curr_task_map, &key);
		if (!cpu_curr_task_ctx || !(cpu_curr_task_ctx->valid))
		{
			bpf_printk("[DEBUG] [HELPER] Prev cpu (%d) was idle", prev_cpu);
			return prev_cpu;
		}	
	}
	
	// Look for any other idle cpu
	s32 cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
	{
		struct cpu_curr_task* cpu_curr_task_ctx = bpf_map_lookup_elem(&cpu_curr_task_map, &cpu);
		if (!cpu_curr_task_ctx || !(cpu_curr_task_ctx->valid))
		{
			bpf_printk("[DEBUG] [HELPER] Found idle cpu (%d) that's in mask", cpu);
			return cpu;
		}
	}

	return -1;
}

static s32 find_lower_priority_cpu(struct task_struct* p)
{
	if (!p)
	{
		return -1;
	}

	struct task_ctx *p_tctx = lookup_task_ctx(p);
	if (p_tctx == NULL)
	{
		return -1;
	}

	bpf_spin_lock(&p_tctx->lock);
	u64 p_abs_deadline = p_tctx->abs_deadline;
	bpf_spin_unlock(&p_tctx->lock);

	struct cpu_curr_task* cpu_curr_task_ctx;
	struct task_ctx *curr_ctx;
	s32 cpu;

	// Loop over the CPUs. Check if there's a sched_ext task dispatched to that CPU.
	// It could be running on the CPU or it could be in the CPU's local DSQ.
	// In either case, the task will be referenced in the CPU's cpu_curr_task_map entry.
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {

		// If the current task can't even run on this cpu, then skip it
		if(!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		{
			continue;
		}

		// Check if there's even a valid cpu_curr_task struct setup for this cpu
		u32 key = cpu;
		cpu_curr_task_ctx = bpf_map_lookup_elem(&cpu_curr_task_map, &key);
		if (!cpu_curr_task_ctx)
		{
			// If not, then skip it
			continue;
		}

		// bool valid_curr_ctx = false;
		// bpf_spin_lock(&cpu_curr_task_ctx->lock);
		// valid_curr_ctx = (cpu_curr_task_ctx->curr_ctx != NULL);
		// bpf_spin_unlock(&cpu_curr_task_ctx->lock);
		
		// There isn't a sched_ext task already dispatched to this cpu, then skip it
		// if (cpu_curr_task_ctx->curr_ctx == NULL)
		// {
		// 	continue;
		// }

		if (!(cpu_curr_task_ctx->valid))
		{
			continue;
		}

		// bpf_spin_lock(&curr_ctx->lock);
		u64 curr_task_abs_dl = cpu_curr_task_ctx->curr_abs_dl;
		bool valid = cpu_curr_task_ctx->valid;
		int curr_pid = cpu_curr_task_ctx->curr_pid;
		// bpf_spin_unlock(&curr_ctx->lock);

		if (!valid)
		{
			continue;
		}

		if (curr_task_abs_dl > p_abs_deadline)
		{
			bpf_printk(
				"[INFO] [ENQUEUE] Task pid=%d (abs_deadline %llu) preempting running task pid=%d (abs_deadline %llu) on core %d, because it has an earlier deadline\n", 
				p->pid, p_abs_deadline, curr_pid, curr_task_abs_dl, cpu
			);
			return cpu;
		}
	}
	return -1;
}

static s32 insert_task_into_deadline_wheel_bucket(struct task_ctx *p_tctx, u64 bucket_idx)
{
	if (p_tctx == NULL)
	{
		return -1;
	}
	if (!(p_tctx->valid))
	{
		scx_bpf_error("Tried to insert task_ctx into bucket, but task_ctx->valid==false");
		return -1;
	}

	struct deadline_wheel_slot* bucket;
	if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
		scx_bpf_error("Failed to get bucket idx %llu pointer, after creating it", bucket_idx);
		return -ENOMEM;
	}

	// bpf_spin_lock(&bucket->lock);
	slock(&bucket->sem);
	bpf_printk("[INSERT] Got bucket->sem lock!!");
	list_head = bucket->head_ptr;
	p_tctx->atnode->bucket = bucket_idx;
	struct arena_task_node __arena * atnode = NULL;
	int error = 0;
	list_for_each_entry(atnode, bucket->head_ptr, node)
	{
		if (atnode->pid == p_tctx->atnode->pid)
		{
			error = 1;
			break;
		}
	}
	list_add_head(&p_tctx->atnode->node, list_head);
	p_tctx->atnode->in_bucket = true;
	bucket->bucket_count++;
	// bpf_spin_unlock(&bucket->lock);
	__sync_val_compare_and_swap(&bucket->sem, 1, 0);
	print_bucket_list(bucket_idx, bucket);
	if (error)
	{
		bpf_printk("Re-insertion error\n");
		scx_bpf_error("Error, pid %d was already in list, but re-inserted it again.", p_tctx->atnode->pid);
	}
	
	
	bpf_printk("Inserted pid %d into deadline wheel bucket %llu. Num tasks in bucket = %d\n", p_tctx->pid, bucket_idx, bucket->bucket_count);
	
	// int u64_array_idx = bucket_idx / 64;
	// int bit_idx = bucket_idx % 64;
	// bucket_bitmask_array[u64_array_idx] |= (1 << bit_idx);
	// bpf_printk("Enabled bit for bucket index %llu; array idx = %d, bit idx = %d, bucket_bitmask_array[%d]=0x%x\n", 
	// 		bucket_idx, u64_array_idx, bit_idx, u64_array_idx, bucket_bitmask_array[u64_array_idx]);

	u32 bitmask_key = 0;
	struct bucket_bitmask_data *b_data =
		bpf_map_lookup_elem(&bucket_bitmask_map, &bitmask_key);
	if (b_data) {
		// bpf_spin_lock(&b_data->lock);
		slock(&b_data->sem);
		bpf_printk("[INSERT] Got b_data lock!!!");
		set_bitmask_tree(b_data, bucket_idx);
		// bpf_spin_unlock(&b_data->lock);
		__sync_val_compare_and_swap(&b_data->sem, 1, 0);
	}

	if (bucket->bucket_count < 0)
	{
		scx_bpf_error("[ERROR] [HELPER] Number of tasks in bucket %llu is %d\n", bucket_idx, bucket->bucket_count);
	}

	
	return 0;
}

void BPF_STRUCT_OPS(deadline_wheel_enqueue, struct task_struct *p, u64 enq_flags)
{
    BPF_ASSERT(p->policy == 7);
	scx_arena_subprog_init();
	bpf_printk("[INFO] [ENQUEUE] Enqueueing task %d (%s).\n", p->pid, p->comm);
	//Check for any idle CPUs this task can run on
	s32 idle_cpu;
	if (!(enq_flags & SCX_ENQ_REENQ) && !(enq_flags & SCX_ENQ_CPU_SELECTED) && (idle_cpu = find_idle_cpu(p, scx_bpf_task_cpu(p))) >= 0) {
		bpf_printk("[INFO] [ENQUEUE] Enqueued task %d (%s) directly in cpu %d local dsq.\n", p->pid, p->comm, idle_cpu);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | idle_cpu, SCX_SLICE_INF, enq_flags | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT);
		scx_bpf_kick_cpu(idle_cpu, SCX_KICK_PREEMPT);
		return;
	}

	// Check if there's a sched_ext task dispatched to a CPU, which has a later absolute deadline
	s32 lower_priority_cpu = find_lower_priority_cpu(p);
	if (lower_priority_cpu >= 0)
	{
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | lower_priority_cpu, SCX_SLICE_INF, enq_flags | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT);
		scx_bpf_kick_cpu(lower_priority_cpu, SCX_KICK_PREEMPT);
		return;
	}

	// There was no idle CPU or lower priority task to preempt. Insert into the deadline wheel
	struct task_ctx *p_tctx = lookup_task_ctx(p);
	if (p_tctx == NULL)
	{
		scx_bpf_error("task_ctx does not exist for %d in enqueue.", p->pid);
		return;
	}
	// scx_bpf_dsq_insert(p, FALLBACK_DSQ_ID, SCX_SLICE_INF, enq_flags);
	u64 bucket_idx = (p_tctx->abs_deadline) % NUM_BUCKETS;
	bpf_printk("[INFO] [ENQUEUE] No idle CPU or CPU w/ lower priority task. Putting pid %d (abs_deadline %llu) into bucket %llu\n", 
			p->pid, p_tctx->abs_deadline, bucket_idx);
	insert_task_into_deadline_wheel_bucket(p_tctx, bucket_idx);
}
void BPF_STRUCT_OPS(deadline_wheel_running, struct task_struct *p)
{
	u32 cpu = scx_bpf_task_cpu(p);
	struct cpu_curr_task* curr_task;
	curr_task = bpf_map_lookup_elem(&cpu_curr_task_map, &cpu);
	if (!curr_task)
	{
		scx_bpf_error("Failed to find cpu_curr_task_map for cpu %d", cpu);
		return;
	}

	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, 0))) {
		scx_bpf_error("task_ctx lookup failed in running");
		return;
	}
	if (!tctx->valid)
	{
		scx_bpf_error("Pid %d's task_ctx is invalid in running", p->pid);
		return;
	}

	bpf_spin_lock(&curr_task->lock);
	curr_task->valid = true;
	curr_task->curr_pid = p->pid;
	curr_task->curr_abs_dl = tctx->abs_deadline;
	bpf_spin_unlock(&curr_task->lock);
	
	u64 now = scx_bpf_now();
	bpf_printk("[INFO] [RUNNING] Running task %d (%s) on cpu %d (Abs. DL = %llu) [slice=%llu]\n", p->pid, p->comm, cpu, tctx->abs_deadline, p->scx.slice);
}

void BPF_STRUCT_OPS(deadline_wheel_stopping, struct task_struct *p, bool runnable)
{
	u64 now = scx_bpf_now();
	u32 cpu = scx_bpf_task_cpu(p);
	bpf_printk("[INFO] [STOPPING] Stopping task %d (%s) on cpu %d, [slice=%llu][runnable = %d]\n", p->pid, p->comm, cpu, p->scx.slice, (int)runnable);
	struct cpu_curr_task* curr_task;
	curr_task = bpf_map_lookup_elem(&cpu_curr_task_map, &cpu);
	if (!curr_task)
	{
		scx_bpf_error("Failed to find cpu_curr_task_map for cpu %d", cpu);
		return;
	}

	if (!curr_task->valid)
	{
		scx_bpf_error("curr_task struct on cpu %d is marked invalid in stopping", cpu);
		return;
	}

	// bpf_printk("[%llu] [INFO] [STOPPING] Stopping task %d (%s) on cpu %d (Abs. DL = %llu)\n", now, p->pid, p->comm, cpu, curr_task->curr_abs_dl);

	bpf_spin_lock(&curr_task->lock);
	curr_task->valid = false;
	curr_task->curr_pid = -1;
	curr_task->curr_abs_dl = 0x7FFFFFFFFFFFFFFFULL;
	bpf_spin_unlock(&curr_task->lock);
}

struct bucket_loop_data {
	u64 start_bucket;
	bool found_task;
	u64 found_task_bucket;
	int pid;
	s32 cpu;
};

static inline struct task_ctx* fetch_from_bucket(u64 bucket_idx, struct bucket_bitmask_data *b_data, s32 cpu){
	struct deadline_wheel_slot* bucket;
	struct task_ctx* ctx = NULL;
	if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
		return NULL;
		// scx_bpf_error("Failed to get bucket idx %llu pointer, after creating it", bucket_idx);
	}
	slock(&bucket->sem);
	bpf_printk("[FETCH] Got bucket->sem lock!!!!");
	if (bucket->bucket_count == 0)
	{
		goto done;
	}
	if (!bucket->head_ptr)
	{
		return NULL;
		// scx_bpf_error("Invalid bucket head pointer for bucket %llu.", bucket_idx);
	}

	struct arena_task_node __arena* atnode = NULL;
	list_for_each_entry(atnode, bucket->head_ptr, node)	
	{
		struct task_struct *tstruct = bpf_task_from_pid(atnode->pid);
	    if (!tstruct) {
			return NULL;
		    // scx_bpf_error(
			//     "Invalid task_struct pointer for 'found' task_ctx (pid = %d)",
			//     atnode->pid);
	    }
		bool can_run_on_cpu = bpf_cpumask_test_cpu(cpu, tstruct->cpus_ptr);
		bpf_task_release(tstruct);
	    if (can_run_on_cpu) {
		    list_del(&atnode->node);
			atnode->in_bucket = false;
			bucket->bucket_count--;
			if(bucket->bucket_count==0){
				// bpf_spin_lock(&b_data->lock);
				clear_bitmask_tree(b_data, bucket_idx);
				// bpf_spin_unlock(&b_data->lock);
				
				// bpf_printk(
				// 	"[FETCH_FROM_BUCKET] Disabled bit using clear_bitmask_tree for bucket index %llu",
				// 	bucket_idx);
			}
			break;
	    }
	}

	done:
	__sync_val_compare_and_swap(&bucket->sem, 1, 0);
	return ctx;
}

// static inline long check_deadline_wheel_slot(u64 iteration, void* ctx)
// {
// 	struct bucket_loop_data* bucket_data = (struct bucket_loop_data*)ctx;

// 	u64 bucket_idx = (iteration + bucket_data->start_bucket) % NUM_BUCKETS;
// 	struct deadline_wheel_slot* bucket;
// 	if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
// 		scx_bpf_error("Failed to get bucket idx %llu pointer, after creating it", bucket_idx);
// 		return 1;
// 	}

// 	bpf_spin_lock(&bucket->lock);
// 	if (bucket->bucket_count == 0)
// 	{
// 		bpf_spin_unlock(&bucket->lock);
// 		return 0;
// 	}

// 	if (!bucket->head_ptr)
// 	{
// 		bpf_spin_unlock(&bucket->lock);
// 		scx_bpf_error("Invalid bucket head pointer for bucket %llu.", bucket_idx);
// 		return 1;
// 	}
// 	struct arena_task_node __arena* atnode = NULL;
// 	list_for_each_entry(atnode, bucket->head_ptr, node)	
// 	{
// 		u64 mask = ((u64)(1 << bucket_data->cpu)) & atnode->cpumask;
// 		if (!mask)
// 		{
// 			continue;
// 		}

// 		list_del(&atnode->node);
// 		atnode->in_bucket = false;
// 		bucket->bucket_count--;
// 		bucket_data->found_task = true;
// 		bucket_data->found_task_bucket = bucket_idx;
// 		bucket_data->pid = atnode->pid;
// 		break;
// 	}

// 	bpf_spin_unlock(&bucket->lock);
	
// 	if (bucket_data->found_task)
// 	{	
// 		struct arena_task_node __arena* atnode2 = NULL;
// 		int error = 0;
// 		bpf_spin_lock(&bucket->lock);
// 		list_for_each_entry(atnode2, bucket->head_ptr, node)
// 		{
// 			if (atnode2->pid == bucket_data->pid)
// 			{
// 				error = 1;
// 				break;
// 			}
// 		}
// 		bpf_spin_unlock(&bucket->lock);
// 		if (error)
// 		{
// 			bpf_printk("Not removed error.\n");
// 			print_bucket_list(bucket_idx, bucket);
// 			scx_bpf_error("Error, pid %d was still in list, after removing it.", bucket_data->pid);
// 		}

// 		if (((&atnode->node)->next != LIST_POISON1))
// 				scx_bpf_error("deleted node->next %x != LIST_POISON1(%x)", (u64)((&atnode->node)->next), (u64)(LIST_POISON1));
// 		if (((&atnode->node)->pprev != LIST_POISON2))
// 			scx_bpf_error("deleted node->pprev %x != LIST_POISON2(%x)", (u64)((&atnode->node)->pprev), (u64)(LIST_POISON2));
		
// 		bpf_printk("[INFO] [DISPATCH] Removed pid %d from bucket %llu. %d tasks remain in bucket\n", bucket_data->pid, bucket_idx, bucket->bucket_count);
// 		bpf_printk("[INFO] [DISPATCH] [CPU%d] Found node 0x%x (atnode = 0x%x) of task %d in bucket %llu. Mask=0x%x\n", 
// 		bucket_data->cpu, &atnode->node, atnode, bucket_data->pid, bucket_idx, atnode->cpumask);
// 		print_bucket_list(bucket_idx, bucket);
// 		if (bucket->bucket_count < 0)
// 		{
// 			scx_bpf_error("[ERROR] [DISPATCH] Number of tasks in bucket %llu is %d\n", bucket_idx, bucket->bucket_count);
// 		}
// 		return 1;
// 	}
// 	return 0;
// }

void BPF_STRUCT_OPS(deadline_wheel_dispatch, s32 cpu, struct task_struct *prev)
{
	// if (cpu != 2 && cpu !=3) return;
	// if (cpu != 2) return;
	bpf_printk("[INFO] [DISPATCH] CPU %d dispatching\n", cpu);
    if (inited == 0) return;
	scx_arena_subprog_init();
	// if (prev && prev->policy == 7)
	// {
	// 	bpf_printk("[INFO] [DISPATCH] CPU %d dispatching from deadline wheel. Prev was pid %d (%s)(policy %d) with slice %llu.\n", cpu, prev->pid, prev->comm, prev->policy, prev->scx.slice);
	// }
	// bpf_printk("[INFO] [DISPATCH] CPU %d dispatching from deadline wheel.\n", cpu);

	// u64 curr_time_ns = scx_bpf_now();
	// u64 curr_time_bucket_idx = curr_time_ns % NUM_BUCKETS;

	// struct bucket_loop_data bucket_data;
	// // bucket_data.start_bucket = curr_time_bucket_idx;
	// bucket_data.start_bucket = 0;
	// bucket_data.found_task = false;
	// bucket_data.found_task_bucket = 0x7FFFFFFFFFFFFFFFULL;
	// bucket_data.pid = -1;
	// bucket_data.cpu = cpu;

	// bpf_printk("[INFO] [DISPATCH] Checking buckets starting with #%llu\n", curr_time_bucket_idx);
	// u64 iterations = NUM_BUCKETS;
    // void *loop_ctx = (void*)&bucket_data;
    // bpf_loop(iterations, check_deadline_wheel_slot, loop_ctx, 0);


    // int highest_nonempty_idx = get_highest_bit(bucket_bitmask_array[0]);
	// bpf_printk("[INFO] [DISPATCH] highest_nonempty_idx: %d 0x%x", highest_nonempty_idx, bucket_bitmask_array[0]);
	u32 bucket_bitmask_key=0;
	struct bucket_bitmask_data *b_data = bpf_map_lookup_elem(&bucket_bitmask_map, &bucket_bitmask_key);
	struct task_ctx* tctx = NULL;
	u64 highest_nonempty_idx;
	if(b_data){
		// bpf_spin_lock(&b_data->lock);
		slock(&b_data->sem);
		bpf_printk("[DISPATCH] Got b_data->sem lock!!!");
		// int highest_nonempty_idx = get_highest_bit(b_data->bitmasks[0]);
		highest_nonempty_idx = get_highest_bitmask_tree(b_data);
		// bpf_printk("[INFO] [DISPATCH] highest_nonempty_idx: %d", highest_nonempty_idx);
		if(highest_nonempty_idx==-1) {bpf_printk("[INFO] [DISPATCH] Deadline wheel is empty");}
		// if(highest_nonempty_idx==-1){}
		else{
		// bool check = check_deadline_wheel_slot(highest_nonempty_idx,
		// 				       loop_ctx);
		// if (check) {bpf_printk("[INFO] [DISPATCH] correctly identified bucket!");}
		// else {bpf_printk("[INFO] [DISPATCH] problem identifying correct bucket!");}
			tctx = fetch_from_bucket(highest_nonempty_idx, b_data, cpu);
			if(tctx==NULL) {bpf_printk("[DISPATCH] Found %d but bucket was empty", highest_nonempty_idx);}
		}
		// bpf_spin_unlock(&b_data->lock);
		__sync_val_compare_and_swap(&b_data->sem, 1, 0);
	}
	if(!b_data || !tctx) {return;}
    
	    // if (bucket_data.pid == -1) {
		//     scx_bpf_error(
		// 	    "bucket_data.pid == -1 but bucket_data.found_task_bucket==true");
		//     return;
	    // }
	    // int pid = bucket_data.pid;
	    // struct task_struct *tstruct = bpf_task_from_pid(pid);
	    // if (!tstruct) {
		//     scx_bpf_error(
		// 	    "Invalid task_struct pointer for 'found' task_ctx (pid = %d)",
		// 	    pid);
		//     return;
	    // }

	    // bool can_run_on_cpu = bpf_cpumask_test_cpu(cpu, tstruct->cpus_ptr);
	    // if (!can_run_on_cpu) {
		//     bpf_printk(
		// 	    "[INFO] [DISPATCH] Error: task %d's real mask %llu doesn't match its task_ctx mask. Returning to bucket %llu.\n",
		// 	    tstruct->pid, (u64) * (int *)tstruct->cpus_ptr,
		// 	    bucket_data.found_task_bucket);
		//     insert_task_into_deadline_wheel_bucket(
		// 	    tstruct, bucket_data.found_task_bucket);
		//     bpf_task_release(tstruct);
		//     return;
	    // }

	    // int u64_array_idx = bucket_data.found_task_bucket / 64;
	    // int bit_idx = bucket_data.found_task_bucket % 64;
	    // bucket_bitmask_array[u64_array_idx] =
		//     bucket_bitmask_array[u64_array_idx] & ~(1 << bit_idx);
	    // bpf_printk(
		//     "Disabled bit for bucket index %llu; array idx = %d, bit idx = %d, bucket_bitmask_array[%d]=0x%x\n",
		//     bucket_data.found_task_bucket, u64_array_idx, bit_idx,
		//     u64_array_idx, bucket_bitmask_array[u64_array_idx]);

	    // struct deadline_wheel_slot *bucket = bpf_map_lookup_elem(&dl_wheel, &highest_nonempty_idx);
		// if(bucket==NULL){
		// 	scx_bpf_error("[DISPATCH] Critical Error!");
		// 	return;
		// }

		// if(bucket->bucket_count==0){
		// 	bpf_spin_lock(&b_data->lock);
		//     clear_bitmask_tree(b_data, highest_nonempty_idx);
		//     bpf_spin_unlock(&b_data->lock);
		//     bpf_printk(
		// 	    "[DISPATCH] Disabled bit using clear_bitmask_tree for bucket index %llu",
		// 	    highest_nonempty_idx);
		// }
		    

		    int pid = tctx->pid;
			struct task_struct *tstruct = bpf_task_from_pid(pid);
			if (!tstruct) {
				scx_bpf_error(
					"Invalid task_struct pointer for 'found' task_ctx (pid = %d)",
					pid);
				return;
			}
			scx_bpf_dsq_insert(tstruct, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, SCX_ENQ_HEAD|SCX_ENQ_PREEMPT);
		    // u64 mask = (u64) * (int *)tstruct->cpus_ptr;
		    bpf_task_release(tstruct);

		    // bool success = false;
		    // struct task_struct *p;
		    // bpf_for_each(scx_dsq, p, FALLBACK_DSQ_ID, 0) {
			//     if (p->pid == pid) {
			// 	    scx_bpf_dsq_move_set_slice(
			// 		    BPF_FOR_EACH_ITER, SCX_SLICE_INF);
			// 	    success = scx_bpf_dsq_move(
			// 		    BPF_FOR_EACH_ITER, p,
			// 		    SCX_DSQ_LOCAL_ON | cpu,
			// 		    SCX_ENQ_HEAD); //|SCX_ENQ_PREEMPT);
			// 	    if (!success) {
			// 		    scx_bpf_error(
			// 			    "[INFO] [DISPATCH] Failed to dispatch task %d (mask=%llu) to cpu %d\n",
			// 			    pid, mask, cpu);
			// 	    }
			// 	    bpf_printk(
			// 		    "[INFO] [DISPATCH] Dispatched task %d (mask=%llu) to cpu %d\n",
			// 		    p->pid, mask, cpu);

			// 	    break;
			//     }
		    // }
		    // scx_bpf_dsq_insert(tstruct, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, SCX_ENQ_HEAD|SCX_ENQ_PREEMPT);

			bpf_printk("[DISPATCH] Cpu %d dispatched task %d", cpu, pid);

} 
		// else {
		//     s32 num_fallback = scx_bpf_dsq_nr_queued(FALLBACK_DSQ_ID);
		//     if (num_fallback > 0) {
		// 		bpf_printk("Fallback DSQ contents:");
		// 	    struct task_struct *pt;
		// 		bpf_for_each(scx_dsq, pt, FALLBACK_DSQ_ID, 0) 
		// 		{
		// 			bpf_printk("%i\n", pt->pid);
		// 		}
		// 		bpf_printk(
		// 		    "Couldn't find a task in the deadline wheel, but the fallback dsq isn't empty (%d tasks).\n",
		// 		    num_fallback);
		//     }
	    // }

SEC("tp_btf/sched_switch")
int BPF_PROG(deadline_wheel_sched_switch, bool preempt, struct task_struct *prev,
         struct task_struct *next, unsigned long prev_state)
{
    if (!__COMPAT_scx_bpf_reenqueue_local_from_anywhere())
        return 0;

	bool is_kthread = (next->flags & PF_KTHREAD);

    // Core is getting taken by a task of a higher-priority scheduling class.
    // This next task isn't a kthread, so it might take a while before sched-ext gets the core again. 
    // Reenqueue local DSQ tasks in the meantime so they can run elsewhere.
    if (preempt && !is_kthread) {
        scx_bpf_reenqueue_local();
		int cpu = bpf_get_smp_processor_id();
		if (prev->policy == 7 && next->policy != 7)
		{
			bpf_printk("[DEBUG] [SCHED-SWITCH] CPU %d is released, next prio: %u, next pid: %lu, next comm: %s, kthread: %d\n", 
				cpu, next->prio, next->pid, next->comm, is_kthread);
		}
    }

    return 0;
}

void BPF_STRUCT_OPS(deadline_wheel_quiescent, struct task_struct *p, u64 deq_flags) {
	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);
	if (deq_flags & SCX_DEQ_CORE_SCHED_EXEC)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) going quiescent on cpu %d, because the generic core-sched layer decided to execute the task even though it hasn't been dispatched yet. Dequeue from the BPF side.\n", p->pid, p->comm, cpu);
	if (deq_flags & 0x01)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) quiescent because it's being sleeped\n", p->pid, p->comm);
	 if (deq_flags & 0x02)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) quiescent because it's being saved\n", p->pid, p->comm);
	 if (deq_flags & 0x04)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) quiescent because it's being moved\n", p->pid, p->comm);
	 if (deq_flags & 0x08)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) quiescent because no clock\n", p->pid, p->comm);
	 if (deq_flags & 0x10)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) quiescent because special\n", p->pid, p->comm);
	 if (deq_flags & 0x100)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) quiescent because migrating\n", p->pid, p->comm);
	 if (deq_flags & 0x200)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) quiescent because delayed\n", p->pid, p->comm);
	
	bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) going quiescent [slice=%llu]\n", p->pid, p->comm, p->scx.slice);
}

void BPF_STRUCT_OPS(deadline_wheel_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = scx_bpf_now();
	bool enqueue_restore = enq_flags & 0x0002;
	if (enq_flags &  SCX_ENQ_WAKEUP )
	{
		bpf_printk("[INFO] [RUNNABLE] Task %d (%s) [slice=%llu] is runnable (waking up) [ENQUEUE_RESTORE=%d]\n", p->pid, p->comm, p->scx.slice, enqueue_restore);
	}
	else
	{
		bpf_printk("[INFO] [RUNNABLE] Task %d (%s) [slice=%llu] is runnable (migrated or restored after attribute change) [ENQUEUE_RESTORE=%d]\n", p->pid, p->comm, p->scx.slice, enqueue_restore);
	}
}

void BPF_STRUCT_OPS(deadline_wheel_dequeue, struct task_struct *p, u64 deq_flags)
{
	scx_arena_subprog_init();
	if (deq_flags & SCX_DEQ_SLEEP)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because it's no longer runnable\n", p->pid, p->comm);
	else if (deq_flags & SCX_DEQ_CORE_SCHED_EXEC)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because the generic core-sched layer decided to execute the task even though it hasn't been dispatched yet. Dequeue from the BPF side.\n", p->pid, p->comm);
	else if (deq_flags & 0x04)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because it's being moved\n", p->pid, p->comm);
	else if (deq_flags & 0x08)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because no clock\n", p->pid, p->comm);
	else if (deq_flags & 0x10)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because special\n", p->pid, p->comm);
	else if (deq_flags & 0x100)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because migrating\n", p->pid, p->comm);
	else if (deq_flags & 0x200)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because delayed\n", p->pid, p->comm);
	else
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued\n", p->pid, p->comm);

	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, 0))) {
		scx_bpf_error("task_ctx lookup failed in running");
		return;
	}

	u64 bucket_idx = tctx->atnode->bucket;
	struct deadline_wheel_slot* bucket;
	if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
		scx_bpf_error("Failed to get bucket idx %llu pointer, after creating it", bucket_idx);
		return;
	}

	bpf_spin_lock(&bucket->lock);
	if (bucket->bucket_count == 0)
	{
		bpf_spin_unlock(&bucket->lock);
		return;
	}

	int not_in_bucket = 0;
	if(tctx->atnode)
	{
		if (!(tctx->atnode->in_bucket))
		{
			not_in_bucket = 1;

		}
		list_del(&tctx->atnode->node);
		tctx->atnode->in_bucket = false;
		bucket->bucket_count--;
	}
	bpf_spin_unlock(&bucket->lock);

	if(tctx->atnode)
	{
		if (not_in_bucket)
		{
			scx_bpf_error("[ERROR] [DEQUEUE] Error: Tried to dequeue pid %d, but its not in a bucket.", tctx->atnode->pid);
		}
	
		struct arena_task_node __arena* atnode2 = NULL;
		int error = 0;
		bpf_spin_lock(&bucket->lock);
		list_for_each_entry(atnode2, bucket->head_ptr, node)
		{
			if (atnode2->pid == tctx->atnode->pid)
			{
				error = 1;
				break;
			}
		}
		bpf_spin_unlock(&bucket->lock);
		if (error)
		{
			bpf_printk("Not removed error.\n");
			print_bucket_list(bucket_idx, bucket);
			scx_bpf_error("Error, pid %d was still in list, after removing it.", tctx->atnode->pid);
		}
	}

	// int u64_array_idx = bucket_idx / 64;
	// int bit_idx = bucket_idx % 64;
	// bucket_bitmask_array[u64_array_idx] = bucket_bitmask_array[u64_array_idx] & ~(1 << bit_idx);
	// bpf_printk("[DEQUEUE] Disabled bit for bucket index %llu; array idx = %d, bit idx = %d, bucket_bitmask_array[%d]=0x%x\n", 
	// 	bucket_idx, u64_array_idx, bit_idx, u64_array_idx, bucket_bitmask_array[u64_array_idx]);

	if (((&tctx->atnode->node)->next != LIST_POISON1))
		scx_bpf_error("deleted node->next %x != LIST_POISON1(%x)", (u64)((&tctx->atnode->node)->next), (u64)(LIST_POISON1));
	if (((&tctx->atnode->node)->pprev != LIST_POISON2))
		scx_bpf_error("deleted node->pprev %x != LIST_POISON2(%x)", (u64)((&tctx->atnode->node)->pprev), (u64)(LIST_POISON2));
	bpf_printk("[INFO] [DEQUEUE] Removed pid %d from bucket %llu. %d tasks remain in bucket\n", p->pid, bucket_idx, bucket->bucket_count);
	print_bucket_list(bucket_idx, bucket);
	if (bucket->bucket_count < 0)
	{
		scx_bpf_error("[ERROR] [DEQUEUE] Number of tasks in bucket %llu is %d\n", bucket_idx, bucket->bucket_count);
	}
}

void BPF_STRUCT_OPS(deadline_wheel_dump, struct scx_dump_ctx *dctx)
{
	scx_arena_subprog_init();
	scx_bpf_dump("Deadline Wheel Scheduler Dump:\n");
	int num_cpus = scx_bpf_nr_cpu_ids();
	scx_bpf_dump("Num cpus: %d\n", num_cpus);
	int cpu;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) 
	{
		struct cpu_curr_task* curr_task = bpf_map_lookup_elem(&cpu_curr_task_map, &cpu);
		if (!curr_task)
		{
			continue;
		}
		if (curr_task->valid)
		{
			scx_bpf_dump("CPU %d: pid=%d, abs_dl=%llu\n", cpu, curr_task->curr_pid, curr_task->curr_abs_dl);
		}
		else 
		{
			scx_bpf_dump("CPU %d: No SCX task\n", cpu);
		}
	}

	scx_bpf_dump("Deadline Wheel:\n");
	for (u64 i = 0; i < NUM_BUCKETS; i++)
	{
		struct deadline_wheel_slot* bucket;
		if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &i))) {
			continue;
		}
		scx_bpf_dump("[%llu][%d tasks]: ", i, bucket->bucket_count);
		struct arena_task_node __arena * atnode = NULL;
		list_for_each_entry(atnode, bucket->head_ptr, node)
		{
			scx_bpf_dump("\t%d->", atnode->pid);
		}
		scx_bpf_dump("\n");
	}

	int i;
	struct task_struct* p;
	scx_bpf_dump("[TIMER] FALLBACK_DSQ_ID contents:\n");
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, FALLBACK_DSQ_ID, 0) 
	{
		scx_bpf_dump("%i\n", p->pid);
	}
	bpf_rcu_read_unlock();
	scx_bpf_dump("[TIMER] FALLBACK_DSQ_ID end of contents.\n");

	bpf_for(i, 2, 4) 
	{
		s32 num_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | i);
		scx_bpf_dump("[TIMER] CPU %d DSQ contents:\n", i);
		bpf_rcu_read_lock();
		bpf_for_each(scx_dsq, p, SCX_DSQ_LOCAL_ON | i, 0) 
		{
			scx_bpf_dump("%i\n", p->pid);
		}
		bpf_rcu_read_unlock();
		scx_bpf_dump("[TIMER] CPU %d DSQ end of contents.\n", i);
	}
}

void BPF_STRUCT_OPS(deadline_exit_task, struct task_struct *p, struct scx_exit_task_args *args){
	s32 pid = p->pid;
	bpf_map_delete_elem(&task_relative_deadlines_map, &pid);
	bpf_printk("[EXIT_TASK] deleting task %d", pid);
}

SCX_OPS_DEFINE(deadline_wheel_ops,
	.flags			= SCX_OPS_ENQ_LAST | SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_MIGRATION_DISABLED,
	.name			= "deadline",
	.init			= (void *)deadline_wheel_init,
	.exit			= (void *)deadline_wheel_exit,
	.enable			= (void *)deadline_wheel_enable,
	.disable		= (void *)deadline_wheel_disable,
	.select_cpu		= (void *)deadline_wheel_select_cpu,
	.enqueue		= (void *)deadline_wheel_enqueue,
	.dequeue		= (void *)deadline_wheel_dequeue,
	.running		= (void *)deadline_wheel_running,
	.stopping		= (void *)deadline_wheel_stopping,
	.dispatch		= (void *)deadline_wheel_dispatch,
	.quiescent		= (void *)deadline_wheel_quiescent,
	.runnable		= (void *)deadline_wheel_runnable,
	.dump			= (void *)deadline_wheel_dump,
	.exit_task 		= (void *)deadline_exit_task
);

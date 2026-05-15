#include <linux/module.h>
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/mm.h>   // MADV_* constants
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("you");
MODULE_DESCRIPTION("Rewrite process_madvise behavior arg to pass validator then restore to MADV_DONTNEED at do_madvise");

#define MADV_WILLNEED 3
#define MADV_DONTNEED 4

/* simple per-task pending set task_keyed by (tgid, tid) */
struct task_key {
    u32 tgid, tid;
};
struct entry {
    struct hlist_node node;
    struct task_key k;
};

DEFINE_HASHTABLE(pending_ht, 8);  // 256 buckets
static DEFINE_SPINLOCK(pending_lock);

static bool pending_has(struct task_key k)
{
    struct entry *e;
    bool found = false;
    unsigned long flags;
    spin_lock_irqsave(&pending_lock, flags);
    hash_for_each_possible(pending_ht, e, node, *(u64*)&k) {
        if (e->k.tgid == k.tgid && e->k.tid == k.tid) { found = true; break; }
    }
    spin_unlock_irqrestore(&pending_lock, flags);
    return found;
}

static void pending_add(struct task_key k)
{
    struct entry *e = kmalloc(sizeof(*e), GFP_ATOMIC);
    unsigned long flags;
    if (!e) return;
    e->k = k;
    spin_lock_irqsave(&pending_lock, flags);
    hash_add(pending_ht, &e->node, *(u64*)&k);
    spin_unlock_irqrestore(&pending_lock, flags);
}

static void pending_del(struct task_key k)
{
    struct entry *e;
    unsigned long flags;
    spin_lock_irqsave(&pending_lock, flags);
    hash_for_each_possible(pending_ht, e, node, *(u64*)&k) {
        if (e->k.tgid == k.tgid && e->k.tid == k.tid) {
            hash_del(&e->node);
            kfree(e);
            break;
        }
    }
    spin_unlock_irqrestore(&pending_lock, flags);
}

/* ... includes and helpers unchanged ... */
/* --- kretprobe handler: remove task from pending set on syscall return --- */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct task_key k = { .tgid = current->tgid, .tid = current->pid };
    pending_del(k);
    return 0;
}

/* ---- hook A: __x64_sys_process_madvise (syscall wrapper) ----
   regs: rdi=pidfd, rsi=vec, rdx=vlen, r10=behavior, r8=flags */
static struct kprobe kp_sys_enter_x64 = {
    .symbol_name = "__x64_sys_process_madvise",
};

static int pre_sys_enter_x64(struct kprobe *p, struct pt_regs *regs)
{
    long behavior = regs->r10;
    if (behavior == MADV_DONTNEED) {
        struct task_key k = { .tgid = current->tgid, .tid = current->pid };
        if (!pending_has(k)) {
            pending_add(k);
            regs->r10 = MADV_WILLNEED;  // 4 -> 3 so validator passes
            pr_info("pmadvise-swap[x64]: %d/%d behavior 4->3 at __x64_sys_process_madvise\n",
                    k.tgid, k.tid);
        }
    }
    return 0;
}

/* ---- hook B: __do_sys_process_madvise (core C-ABI entry) ----
   regs: rdi=pidfd, rsi=vec, rdx=vlen, cx=behavior, r8=flags */
static struct kprobe kp_sys_enter_do = {
    .symbol_name = "__do_sys_process_madvise",
};

static int pre_sys_enter_do(struct kprobe *p, struct pt_regs *regs)
{
    long behavior = regs->cx;  // Ubuntu 6.8 names it 'cx'
    if (behavior == MADV_DONTNEED) {
        struct task_key k = { .tgid = current->tgid, .tid = current->pid };
        if (!pending_has(k)) {
            pending_add(k);
            regs->cx = MADV_WILLNEED;  // 4 -> 3 for validator here
            pr_info("pmadvise-swap[do]: %d/%d behavior 4->3 at __do_sys_process_madvise\n",
                    k.tgid, k.tid);
        }
    }
    return 0;
}

/* ---- existing hook C: do_madvise(mm,start,len,behavior) ----
   regs: rdi=mm, rsi=start, rdx=len, cx=behavior */
static struct kprobe kp_do_madvise = { .symbol_name = "do_madvise" };

static int pre_do_madvise(struct kprobe *p, struct pt_regs *regs)
{
    struct task_key k = { .tgid = current->tgid, .tid = current->pid };
    if (pending_has(k)) {
        regs->cx = MADV_DONTNEED;  // restore to 4 right before work
        pr_info("pmadvise-swap: %d/%d restored behavior to 4 at do_madvise\n", k.tgid, k.tid);
    }
    return 0;
}

/* ---- existing kretprobe on __x64_sys_process_madvise to cleanup ---- */
static struct kretprobe krp_sys_exit = {
    .kp.symbol_name = "__x64_sys_process_madvise",
    .handler = ret_handler,
    .maxactive = 64,
};

static int __init mod_init(void)
{
    int ret;

    /* A) __x64_sys_process_madvise */
    kp_sys_enter_x64.pre_handler = pre_sys_enter_x64;
    ret = register_kprobe(&kp_sys_enter_x64);
    if (ret) { pr_err("kprobe __x64_sys failed: %d\n", ret); return ret; }

    /* B) __do_sys_process_madvise */
    kp_sys_enter_do.pre_handler = pre_sys_enter_do;
    ret = register_kprobe(&kp_sys_enter_do);
    if (ret) {
        pr_err("kprobe __do_sys failed: %d\n", ret);
        unregister_kprobe(&kp_sys_enter_x64);
        return ret;
    }

    /* C) do_madvise */
    kp_do_madvise.pre_handler = pre_do_madvise;
    ret = register_kprobe(&kp_do_madvise);
    if (ret) {
        pr_err("kprobe do_madvise failed: %d\n", ret);
        unregister_kprobe(&kp_sys_enter_do);
        unregister_kprobe(&kp_sys_enter_x64);
        return ret;
    }

    /* D) syscall exit cleanup */
    ret = register_kretprobe(&krp_sys_exit);
    if (ret) {
        pr_err("kretprobe sys_exit failed: %d\n", ret);
        unregister_kprobe(&kp_do_madvise);
        unregister_kprobe(&kp_sys_enter_do);
        unregister_kprobe(&kp_sys_enter_x64);
        return ret;
    }
    pr_info("pmadvise-swap: loaded\n");
    return 0;
}

static void __exit mod_exit(void)
{
    /* unregister in reverse order; free hash as before */
    unregister_kretprobe(&krp_sys_exit);
    unregister_kprobe(&kp_do_madvise);
    unregister_kprobe(&kp_sys_enter_do);
    unregister_kprobe(&kp_sys_enter_x64);
    /* free pending_ht ... (unchanged) */
    pr_info("pmadvise-swap: unloaded\n");
}
module_init(mod_init);
module_exit(mod_exit);


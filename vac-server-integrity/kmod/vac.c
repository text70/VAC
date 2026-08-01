#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/version.h>

#include "vac-ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VAC");
MODULE_DESCRIPTION("VAC Anti-Cheat Kernel Module");

/* ── capabilities ───────────────────────────────────── */

static u32 vac_caps(void)
{
	return VAC_CAP_PROC_LIST | VAC_CAP_READ_MEM | VAC_CAP_PROC_NAME | VAC_CAP_PROTECT;
}

/* ── proc list ──────────────────────────────────────── */

static int vac_fill_proc_list(struct vac_proc_list __user *user_list)
{
	struct task_struct *task;
	u32 i = 0;
	u32 orig_count;

	if (get_user(orig_count, &user_list->count))
		return -EFAULT;

	rcu_read_lock();
	for_each_process(task) {
		if (i >= VAC_MAX_PROCS)
			break;

		/* Skip kernel threads — only user-space processes can be cheats.
		 * PF_KTHREAD is authoritative (mm == NULL is not: io_uring and
		 * other kernel helpers may attach an mm).  User-mode /proc
		 * enumeration mirrors this by skipping kthreadd (pid 2) and its
		 * children, keeping the two views consistent for the hidden/missing
		 * process check.
		 */
		if (task->flags & PF_KTHREAD)
			continue;

		if (put_user(task->pid, &user_list->entries[i].pid)) {
			rcu_read_unlock();
			return -EFAULT;
		}

		{
			__u32 ppid = task->real_parent
				   ? task->real_parent->pid : 0;
			if (put_user(ppid, &user_list->entries[i].ppid)) {
				rcu_read_unlock();
				return -EFAULT;
			}
		}

		{
			__u8 comm[VAC_MAX_COMM] = {0};
			memcpy(comm, task->comm,
			       min(sizeof(task->comm), (size_t)VAC_MAX_COMM - 1));
			if (copy_to_user(user_list->entries[i].comm, comm,
					 VAC_MAX_COMM)) {
				rcu_read_unlock();
				return -EFAULT;
			}
		}
		i++;
	}
	rcu_read_unlock();

	if (put_user(i, &user_list->count))
		return -EFAULT;

	return 0;
}

/* ── read proc mem ──────────────────────────────────── */

static int vac_read_proc_mem(struct vac_read_mem __user *um)
{
	struct vac_read_mem args;
	struct task_struct *task;
	struct mm_struct *mm;
	size_t bytes_read;

	if (copy_from_user(&args, um, sizeof(args)))
		return -EFAULT;

	if (args.size > VAC_READ_SIZE)
		return -EINVAL;

	task = get_pid_task(find_get_pid(args.pid), PIDTYPE_PID);
	if (!task)
		return -ESRCH;

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return -EIO;
	}

	bytes_read = access_process_vm(task, args.address, args.data,
				       args.size, 0);
	mmput(mm);
	put_task_struct(task);

	args.bytes_read = (__u32)bytes_read;

	if (copy_to_user(um, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

/* ── proc name ──────────────────────────────────────── */

static int vac_proc_name(struct vac_proc_name __user *un)
{
	struct vac_proc_name args;
	struct task_struct *task;
	__u8 comm[VAC_MAX_COMM] = {0};

	if (copy_from_user(&args, un, sizeof(args)))
		return -EFAULT;

	task = get_pid_task(find_get_pid(args.pid), PIDTYPE_PID);
	if (!task)
		return -ESRCH;

	memcpy(comm, task->comm,
	       min(sizeof(task->comm), (size_t)VAC_MAX_COMM - 1));
	put_task_struct(task);

	if (copy_to_user(un->comm, comm, VAC_MAX_COMM))
		return -EFAULT;

	return 0;
}

/* ── IOCTL dispatch ─────────────────────────────────── */

static long vac_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case VAC_IOCTL_FILL: {
		u32 caps = vac_caps();
		if (copy_to_user(uarg, &caps, sizeof(caps)))
			return -EFAULT;
		return 0;
	}

	case VAC_IOCTL_PROC_LIST:
		return vac_fill_proc_list(uarg);

	case VAC_IOCTL_READ_MEM:
		return vac_read_proc_mem(uarg);

	case VAC_IOCTL_PROC_NAME:
		return vac_proc_name(uarg);

	default:
		return -ENOTTY;
	}
}

/* ── file operations ────────────────────────────────── */

static const struct file_operations vac_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = vac_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = vac_ioctl,
#endif
};

static struct miscdevice vac_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "vac",
	.fops  = &vac_fops,
};

/* ── module entry / exit ────────────────────────────── */

static int __init vac_init(void)
{
	int ret = misc_register(&vac_misc);
	if (ret)
		pr_err("vac: misc_register failed: %d\n", ret);
	else
		pr_info("vac: loaded (minor %d)\n", vac_misc.minor);
	return ret;
}

static void __exit vac_exit(void)
{
	misc_deregister(&vac_misc);
	pr_info("vac: unloaded\n");
}

module_init(vac_init);
module_exit(vac_exit);

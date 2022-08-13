// nanoBench
//
// Copyright (C) 2019 Andreas Abel
//
// This program is free software: you can redistribute it and/or modify it under the terms of version 3 of the GNU Affero General Public License.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

#include <asm/apic.h>
#include <asm-generic/io.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <../arch/x86/include/asm/fpu/api.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,12,0)
#include <asm/cacheflush.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#include <linux/kallsyms.h>
int (*set_memory_x)(unsigned long,  int) = 0;
int (*set_memory_nx)(unsigned long, int) = 0;
#else
#include <linux/set_memory.h>
#endif

#include "../common/nanoBench.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andreas Abel");

// __vmalloc has no longer the pgprot_t parameter, so we need to hook __vmalloc_node_range directly
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
void *(*kallsym__vmalloc_node_range)(unsigned long size, unsigned long align,
			unsigned long start, unsigned long end, gfp_t gfp_mask,
			pgprot_t prot, unsigned long vm_flags, int node,
			const void *caller);
#endif

// kallsyms_lookup_name is no longer supported; we use a kprobes to get the address
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
unsigned long kallsyms_lookup_name(const char* name) {
  struct kprobe kp = {
    .symbol_name    = name,
  };

  int ret = register_kprobe(&kp);
  if (ret < 0) {
    return 0;
  };

  unregister_kprobe(&kp);

  return (unsigned long) kp.addr;
}
#endif

// 4 Mb is the maximum that kmalloc supports on my machines
#define KMALLOC_MAX (4*1024*1024)

// If enabled, for cycle-by-cycle measurements, the output includes all of the measurement overhead; otherwise, only the cycles between adding the first
// instruction of the benchmark to the IDQ, and retiring the last instruction of the benchmark are considered.
int end_to_end = false;

char* runtime_code_base = NULL;

size_t code_offset = 0;
size_t code_memory_size = 0;
size_t code_init_memory_size = 0;
size_t code_late_init_memory_size = 0;
size_t code_one_time_init_memory_size = 0;
size_t pfc_config_memory_size = 0;
size_t msr_config_memory_size = 0;
size_t runtime_code_base_memory_size = 0;
size_t runtime_one_time_init_code_memory_size = 0;

void** r14_segments = NULL;
size_t n_r14_segments = 0;

static int read_file_into_buffer(const char *file_name, char **buf, size_t *buf_len, size_t *buf_memory_size) {
    struct file *filp = NULL;
    filp = filp_open(file_name, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("Error opening file %s\n", file_name);
        return -1;
    }

    struct path p;
    struct kstat ks;
    kern_path(file_name, 0, &p);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,11,0)
	if (vfs_getattr(&p, &ks)) {
#else
	if (vfs_getattr(&p, &ks, 0, 0)) {
#endif
        pr_err("Error getting file attributes\n");
        return -1;
    }

    size_t file_size = ks.size;
    *buf_len = file_size;

    if (file_size + 1 > *buf_memory_size) {
        kfree(*buf);
        *buf_memory_size = max(2*(file_size + 1), PAGE_SIZE);
        *buf = kmalloc(*buf_memory_size, GFP_KERNEL);
        if (!*buf) {
            pr_err("Could not allocate memory for %s\n", file_name);
            *buf_memory_size = 0;
            filp_close(filp, NULL);
            return -1;
        }
    }

    loff_t pos = 0;
    kernel_read(filp, *buf, file_size, &pos);
    (*buf)[file_size] = '\0';

    path_put(&p);
    filp_close(filp, NULL);
    return 0;
}

static ssize_t code_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return 0;
}
static ssize_t code_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    read_file_into_buffer(buf, &code, &code_length, &code_memory_size);
    return count;
}
static struct kobj_attribute code_attribute =__ATTR(code, 0660, code_show, code_store);

static ssize_t init_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return 0;
}
static ssize_t init_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    read_file_into_buffer(buf, &code_init, &code_init_length, &code_init_memory_size);
    return count;
}
static struct kobj_attribute code_init_attribute =__ATTR(init, 0660, init_show, init_store);

static ssize_t late_init_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return 0;
}
static ssize_t late_init_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    read_file_into_buffer(buf, &code_late_init, &code_late_init_length, &code_late_init_memory_size);
    return count;
}
static struct kobj_attribute code_late_init_attribute =__ATTR(late_init, 0660, late_init_show, late_init_store);

static ssize_t one_time_init_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return 0;
}
static ssize_t one_time_init_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    read_file_into_buffer(buf, &code_one_time_init, &code_one_time_init_length, &code_one_time_init_memory_size);
    size_t new_runtime_one_time_init_code_memory_size = 10000 + code_one_time_init_memory_size;
    if (new_runtime_one_time_init_code_memory_size > runtime_one_time_init_code_memory_size) {
        runtime_one_time_init_code_memory_size = new_runtime_one_time_init_code_memory_size;
        vfree(runtime_one_time_init_code);
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
        runtime_one_time_init_code = kallsym__vmalloc_node_range(runtime_one_time_init_code_memory_size, 1, VMALLOC_START, VMALLOC_END, GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE, __builtin_return_address(0));
        #else
        runtime_one_time_init_code = __vmalloc(runtime_one_time_init_code_memory_size, GFP_KERNEL, PAGE_KERNEL_EXEC);
        #endif
        if (!runtime_one_time_init_code) {
            runtime_one_time_init_code_memory_size = 0;
            pr_err("failed to allocate executable memory\n");
        }
    }
    return count;
}
static struct kobj_attribute code_one_time_init_attribute =__ATTR(one_time_init, 0660, one_time_init_show, one_time_init_store);

static ssize_t config_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    ssize_t count = 0;
    for (int i=0; i<n_pfc_configs; i++) {
        if (is_Intel_CPU) {
            count += snprintf(&(buf[count]), PAGE_SIZE-count, "%02lx.%02lx %s\n", pfc_configs[i].evt_num, pfc_configs[i].umask, pfc_configs[i].description);
        } else {
            count += snprintf(&(buf[count]), PAGE_SIZE-count, "%03lx.%02lx %s\n", pfc_configs[i].evt_num, pfc_configs[i].umask, pfc_configs[i].description);
        }
        if (count > PAGE_SIZE) {
            return PAGE_SIZE-1;
        }
    }
    return count;
}
static ssize_t config_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    size_t pfc_config_length;
    read_file_into_buffer(buf, &pfc_config_file_content, &pfc_config_length, &pfc_config_memory_size);
    parse_counter_configs();
    return count;
}
static struct kobj_attribute config_attribute =__ATTR(config, 0660, config_show, config_store);

static ssize_t msr_config_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    ssize_t count = 0;
    for (int i=0; i<n_msr_configs; i++) {
        struct msr_config config = msr_configs[i];
        for (int j=0; j<config.n_wrmsr; j++) {
            count += sprintf(&(buf[count]), "msr_%lX=0x%lX", config.wrmsr[j], config.wrmsr_val[j]);
            if (j<config.n_wrmsr-1) count += sprintf(&(buf[count]), ".");
        }
        count += sprintf(&(buf[count]), " msr_%lX %s\n", config.rdmsr, config.description);
    }
    return count;
}
static ssize_t msr_config_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    size_t msr_config_length;
    read_file_into_buffer(buf, &msr_config_file_content, &msr_config_length, &msr_config_memory_size);
    parse_msr_configs();
    return count;
}
static struct kobj_attribute msr_config_attribute =__ATTR(msr_config, 0660, msr_config_show, msr_config_store);

static ssize_t fixed_counters_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", use_fixed_counters);
}
static ssize_t fixed_counters_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &use_fixed_counters);
    return count;
}
static struct kobj_attribute fixed_counters_attribute =__ATTR(fixed_counters, 0660, fixed_counters_show, fixed_counters_store);

static ssize_t unroll_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", unroll_count);
}
static ssize_t unroll_count_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%ld", &unroll_count);
    return count;
}
static struct kobj_attribute unroll_count_attribute =__ATTR(unroll_count, 0660, unroll_count_show, unroll_count_store);

static ssize_t loop_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", loop_count);
}
static ssize_t loop_count_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%ld", &loop_count);
    return count;
}
static struct kobj_attribute loop_count_attribute =__ATTR(loop_count, 0660, loop_count_show, loop_count_store);

static ssize_t n_measurements_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", n_measurements);
}
static ssize_t n_measurements_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    long old_n_measurements = n_measurements;
    sscanf(buf, "%ld", &n_measurements);

    if (old_n_measurements < n_measurements) {
        for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
            kfree(measurement_results[i]);
            kfree(measurement_results_base[i]);
            measurement_results[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
            measurement_results_base[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
            if (!measurement_results[i] || !measurement_results_base[i]) {
                pr_err("Could not allocate memory for measurement_results\n");
                return 0;
            }
            memset(measurement_results[i], 0, n_measurements*sizeof(int64_t));
            memset(measurement_results_base[i], 0, n_measurements*sizeof(int64_t));
        }
    }
    return count;
}
static struct kobj_attribute n_measurements_attribute =__ATTR(n_measurements, 0660, n_measurements_show, n_measurements_store);

static ssize_t warm_up_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", warm_up_count);
}
static ssize_t warm_up_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%ld", &warm_up_count);
    return count;
}
static struct kobj_attribute warm_up_attribute =__ATTR(warm_up, 0660, warm_up_show, warm_up_store);

static ssize_t initial_warm_up_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", initial_warm_up_count);
}
static ssize_t initial_warm_up_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%ld", &initial_warm_up_count);
    return count;
}
static struct kobj_attribute initial_warm_up_attribute =__ATTR(initial_warm_up, 0660, initial_warm_up_show, initial_warm_up_store);

static ssize_t alignment_offset_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%zu\n", alignment_offset);
}
static ssize_t alignment_offset_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%zu", &alignment_offset);
    return count;
}
static struct kobj_attribute alignment_offset_attribute =__ATTR(alignment_offset, 0660, alignment_offset_show, alignment_offset_store);

static ssize_t end_to_end_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", end_to_end);
}
static ssize_t end_to_end_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &end_to_end);
    return count;
}
static struct kobj_attribute end_to_end_attribute =__ATTR(end_to_end, 0660, end_to_end_show, end_to_end_store);

static ssize_t drain_frontend_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", drain_frontend);
}
static ssize_t drain_frontend_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &drain_frontend);
    return count;
}
static struct kobj_attribute drain_frontend_attribute =__ATTR(drain_frontend, 0660, drain_frontend_show, drain_frontend_store);

static ssize_t basic_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", basic_mode);
}
static ssize_t basic_mode_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &basic_mode);
    return count;
}
static struct kobj_attribute basic_mode_attribute =__ATTR(basic_mode, 0660, basic_mode_show, basic_mode_store);

static ssize_t no_mem_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", no_mem);
}
static ssize_t no_mem_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &no_mem);
    return count;
}
static struct kobj_attribute no_mem_attribute =__ATTR(no_mem, 0660, no_mem_show, no_mem_store);

static ssize_t no_normalization_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", no_normalization);
}
static ssize_t no_normalization_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &no_normalization);
    return count;
}
static struct kobj_attribute no_normalization_attribute =__ATTR(no_normalization, 0660, no_normalization_show, no_normalization_store);

static ssize_t agg_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", aggregate_function);
}
static ssize_t agg_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    if (!strncmp(buf, "min", 3)) {
        aggregate_function = MIN;
    } else if (!strncmp(buf, "max", 3)) {
        aggregate_function = MAX;
    } else if (!strncmp(buf, "med", 3)) {
        aggregate_function = MED;
    } else {
        aggregate_function = AVG_20_80;
    }
    return count;
}
static struct kobj_attribute agg_attribute =__ATTR(agg, 0660, agg_show, agg_store);

int cmpPtr(const void *a, const void *b) {
    if (*(void**)a == *(void**)b) return 0;
    else if (*(void**)a == NULL) return 1;
    else if (*(void**)b == NULL) return -1;
    else if (*(void**)a < *(void**)b) return -1;
    else return 1;
}

static ssize_t r14_size_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    if (n_r14_segments == 0 || !r14_segments[0]) return sprintf(buf, "0\n");

    void* prev_virt_addr = r14_segments[0];
    phys_addr_t prev_phys_addr = virt_to_phys(prev_virt_addr);

    size_t i;
    for (i=1; i<n_r14_segments; i++) {
        void* cur_virt_addr = r14_segments[i];
        phys_addr_t cur_phys_addr = virt_to_phys(cur_virt_addr);

        if ((cur_virt_addr - prev_virt_addr != KMALLOC_MAX) || (cur_phys_addr - prev_phys_addr != KMALLOC_MAX)) {
            pr_err("No physically contiguous memory area of the requested size found.\n");
            pr_err("Try rebooting your computer.\n");
            break;
        }

        prev_virt_addr = cur_virt_addr;
        prev_phys_addr = cur_phys_addr;
    }

    phys_addr_t phys_addr = virt_to_phys(r14_segments[0]);
    return sprintf(buf, "R14 size: %zu MB\nVirtual address: 0x%px\nPhysical address: %pa\n", i*KMALLOC_MAX/(1024*1024), r14_segments[0], &phys_addr);
}
static ssize_t r14_size_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    if (n_r14_segments > 0) {
        for (int i=0; i<n_r14_segments; i++) {
            kfree(r14_segments[i]);
        }
    } else {
        vfree(runtime_r14 - RUNTIME_R_SIZE/2);
    }

    size_t size_MB = 0;
    sscanf(buf, "%zu", &size_MB);
    n_r14_segments = (size_MB*1024*1024 + (KMALLOC_MAX-1)) / KMALLOC_MAX;
    vfree(r14_segments);
    r14_segments = vmalloc(n_r14_segments * sizeof(void*));

    for (size_t i=0; i<n_r14_segments; i++) {
        r14_segments[i] = kmalloc(KMALLOC_MAX, GFP_KERNEL|__GFP_COMP);
    }

    sort(r14_segments, n_r14_segments, sizeof(void*), cmpPtr, NULL);
    runtime_r14 = r14_segments[0];

    return count;
}
static struct kobj_attribute r14_size_attribute =__ATTR(r14_size, 0660, r14_size_show, r14_size_store);

size_t print_r14_length = 8;
static ssize_t print_r14_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    size_t count = sprintf(buf, "0x");
    for (size_t i=0; i<print_r14_length && i<PAGE_SIZE-3; i++) {
        count += sprintf(&(buf[count]), "%02x", ((unsigned char*)runtime_r14)[i]);
    }
    count += sprintf(&(buf[count]), "\n");
    return count;
}
static ssize_t print_r14_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%zu", &print_r14_length);
    return count;
}
static struct kobj_attribute print_r14_attribute =__ATTR(print_r14, 0660, print_r14_show, print_r14_store);

static ssize_t code_offset_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%zu\n", code_offset);
}
static ssize_t code_offset_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%zu", &code_offset);
    runtime_code = runtime_code_base + code_offset;
    return count;
}
static struct kobj_attribute code_offset_attribute =__ATTR(code_offset, 0660, code_offset_show, code_offset_store);

static ssize_t addresses_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    size_t count = 0;
    count += sprintf(&(buf[count]), "R14: 0x%px\n", runtime_r14);
    count += sprintf(&(buf[count]), "RDI: 0x%px\n", runtime_rdi);
    count += sprintf(&(buf[count]), "RSI: 0x%px\n", runtime_rsi);
    count += sprintf(&(buf[count]), "RBP: 0x%px\n", runtime_rbp);
    count += sprintf(&(buf[count]), "RSP: 0x%px\n", runtime_rsp);
    return count;
}
static ssize_t addresses_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    return 0;
}
static struct kobj_attribute addresses_attribute =__ATTR(addresses, 0660, addresses_show, addresses_store);

static ssize_t verbose_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", verbose);
}
static ssize_t verbose_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &verbose);
    return count;
}
static struct kobj_attribute verbose_attribute =__ATTR(verbose, 0660, verbose_show, verbose_store);

static ssize_t clear_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    code_length = 0;
    code_init_length = 0;
    code_late_init_length = 0;
    code_one_time_init_length = 0;
    return 0;
}
static ssize_t clear_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    return 0;
}
static struct kobj_attribute clear_attribute =__ATTR(clear, 0660, clear_show, clear_store);

static ssize_t reset_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    n_measurements = N_MEASUREMENTS_DEFAULT;
    unroll_count = UNROLL_COUNT_DEFAULT;
    loop_count = LOOP_COUNT_DEFAULT;
    warm_up_count = WARM_UP_COUNT_DEFAULT;
    initial_warm_up_count = INITIAL_WARM_UP_COUNT_DEFAULT;

    no_mem = NO_MEM_DEFAULT;
    no_normalization = NO_NORMALIZATION_DEFAULT;
    basic_mode = BASIC_MODE_DEFAULT;
    use_fixed_counters = USE_FIXED_COUNTERS_DEFAULT;
    aggregate_function = AGGREGATE_FUNCTION_DEFAULT;
    verbose = VERBOSE_DEFAULT;
    alignment_offset = ALIGNMENT_OFFSET_DEFAULT;
    drain_frontend = DRAIN_FRONTEND_DEFAULT;

    end_to_end = false;

    code_init_length = 0;
    code_late_init_length = 0;
    code_one_time_init_length = 0;
    code_length = 0;
    code_offset = 0;
    n_pfc_configs = 0;
    n_msr_configs = 0;

    return 0;
}
static ssize_t reset_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    return 0;
}
static struct kobj_attribute reset_attribute =__ATTR(reset, 0660, reset_show, reset_store);

uint32_t prev_LVTT = 0;
uint32_t prev_LVTTHMR = 0;
uint32_t prev_LVTPC = 0;
uint32_t prev_LVT0 = 0;
uint32_t prev_LVT1 = 0;
uint32_t prev_LVTERR = 0;
uint32_t prev_APIC_TMICT = 0;
uint64_t prev_deadline = 0;

static void restore_interrupts_preemption(void) {
    apic_write(APIC_LVTT, prev_LVTT);
    apic_write(APIC_LVTTHMR, prev_LVTTHMR);
    apic_write(APIC_LVTPC, prev_LVTPC);
    apic_write(APIC_LVT0, prev_LVT0);
    apic_write(APIC_LVT1, prev_LVT1);
    apic_write(APIC_LVTERR, prev_LVTERR);
    apic_write(APIC_TMICT, prev_APIC_TMICT);
    if (supports_tsc_deadline) {
        asm volatile("mfence");
        write_msr(MSR_IA32_TSC_DEADLINE, max(1ULL, prev_deadline));
    }
    prev_LVTT = prev_LVTTHMR = prev_LVTPC = prev_LVT0 = prev_LVT1 = prev_LVTERR = prev_APIC_TMICT = prev_deadline = 0;

    put_cpu();
}

static void disable_interrupts_preemption(void) {
    if (prev_LVTT || prev_LVTTHMR || prev_LVTPC || prev_LVT0 || prev_LVT1 || prev_LVTERR) {
        // The previous call to disable_interrupts_preemption() was not followed by a call to restore_interrupts_preemption().
        restore_interrupts_preemption();
    }

    // disable preemption
    get_cpu();

    // We mask interrupts in the APIC LVT. We do not mask all maskable interrupts using the cli instruction, as on some
    // microarchitectures, pending interrupts that are masked via the cli instruction can reduce the retirement rate
    // (e.g., on ICL to 4 uops/cycle).
    prev_LVTT = apic_read(APIC_LVTT);
    prev_LVTTHMR = apic_read(APIC_LVTTHMR);
    prev_LVTPC = apic_read(APIC_LVTPC);
    prev_LVT0 = apic_read(APIC_LVT0);
    prev_LVT1 = apic_read(APIC_LVT1);
    prev_LVTERR = apic_read(APIC_LVTERR);
    prev_APIC_TMICT = apic_read(APIC_TMICT);
    if (supports_tsc_deadline) {
        prev_deadline = read_msr(MSR_IA32_TSC_DEADLINE);
        write_msr(MSR_IA32_TSC_DEADLINE, 0);
    }

    apic_write(APIC_LVTT, prev_LVTT | APIC_LVT_MASKED);
    apic_write(APIC_LVTTHMR, prev_LVTTHMR | APIC_LVT_MASKED);
    apic_write(APIC_LVTPC, prev_LVTPC | APIC_LVT_MASKED);
    apic_write(APIC_LVT0, prev_LVT0 | APIC_LVT_MASKED);
    apic_write(APIC_LVT1, prev_LVT1 | APIC_LVT_MASKED);
    apic_write(APIC_LVTERR, prev_LVTERR | APIC_LVT_MASKED);
}

static bool check_memory_allocations(void) {
    for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
        if (!measurement_results[i] || !measurement_results_base[i]) {
            pr_err("Could not allocate memory for measurement_results\n");
            return false;
        }
    }

    size_t req_code_length = code_offset + get_required_runtime_code_length();
    if (req_code_length > runtime_code_base_memory_size) {
        pr_err("Maximum supported code size %zu kB; requested %zu kB\n", runtime_code_base_memory_size/1024, req_code_length/1024);
        return false;
    }
    return true;
}

static int run_nanoBench(struct seq_file *m, void *v) {
    if (!check_memory_allocations()) {
        return -1;
    }

    kernel_fpu_begin();
    disable_interrupts_preemption();

    clear_perf_counter_configurations();
    clear_perf_counters();
    clear_overflow_status_bits();
    enable_perf_ctrs_globally();

    long base_unroll_count = (basic_mode?0:unroll_count);
    long main_unroll_count = (basic_mode?unroll_count:2*unroll_count);
    long base_loop_count = (basic_mode?0:loop_count);
    long main_loop_count = loop_count;

    char buf[100];
    char* measurement_template;

    create_and_run_one_time_init_code();
    run_initial_warmup_experiment();

    /*********************************
     * Fixed-function counters.
    ********************************/
    if (use_fixed_counters) {
        if (is_AMD_CPU) {
            if (no_mem) {
                measurement_template = (char*)&measurement_FF_template_AMD_noMem;
            } else {
                measurement_template = (char*)&measurement_FF_template_AMD;
            }
        } else {
            if (no_mem) {
                measurement_template = (char*)&measurement_FF_template_Intel_noMem;
            } else {
                measurement_template = (char*)&measurement_FF_template_Intel;
            }
        }

        if (is_AMD_CPU) {
            run_experiment(measurement_template, measurement_results_base, 3, base_unroll_count, base_loop_count);
            run_experiment(measurement_template, measurement_results, 3, main_unroll_count, main_loop_count);

            if (verbose) {
                pr_info("\nRDTSC, MPERF, and APERF results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
                print_all_measurement_results(measurement_results_base, 3);
                pr_info("RDTSC, MPERF, and and APERF results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
                print_all_measurement_results(measurement_results, 3);
            }

            seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "RDTSC", 0));
            seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "MPERF", 1));
            seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "APERF", 2));
        } else {
            configure_perf_ctrs_FF_Intel(false, true);

            run_experiment(measurement_template, measurement_results_base, 4, base_unroll_count, base_loop_count);
            run_experiment(measurement_template, measurement_results, 4, main_unroll_count, main_loop_count);

            if (verbose) {
                pr_info("\nRDTSC and fixed-function counter results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
                print_all_measurement_results(measurement_results_base, 4);
                pr_info("RDTSC and fixed-function counter results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
                print_all_measurement_results(measurement_results, 4);
            }

            seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "RDTSC", 0));
            seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "Instructions retired", 1));
            seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "Core cycles", 2));
            seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "Reference cycles", 3));
        }
    }

    /*********************************
     * Programmable counters.
     ********************************/
    int n_used_counters = n_programmable_counters;
    if (is_AMD_CPU) {
        if (no_mem) {
            measurement_template = (char*)&measurement_template_AMD_noMem;
        } else {
            measurement_template = (char*)&measurement_template_AMD;
        }
    } else {
        if (n_used_counters >= 4) {
            n_used_counters = 4;
            if (no_mem) {
                 measurement_template = (char*)&measurement_template_Intel_noMem_4;
            } else {
                measurement_template = (char*)&measurement_template_Intel_4;
            }
        } else {
            n_used_counters = 2;
            if (no_mem) {
                measurement_template = (char*)&measurement_template_Intel_noMem_2;
            } else {
                measurement_template = (char*)&measurement_template_Intel_2;
            }
        }
    }

    size_t next_pfc_config = 0;
    while (next_pfc_config < n_pfc_configs) {
        char* pfc_descriptions[MAX_PROGRAMMABLE_COUNTERS] = {0};
        next_pfc_config = configure_perf_ctrs_programmable(next_pfc_config, true, true, n_used_counters, 0, pfc_descriptions);
        // on some microarchitectures (e.g., Broadwell), some events (e.g., L1 misses) are not counted properly if only the OS field is set

        run_experiment(measurement_template, measurement_results_base, n_used_counters, base_unroll_count, base_loop_count);
        run_experiment(measurement_template, measurement_results, n_used_counters, main_unroll_count, main_loop_count);

        if (verbose) {
            pr_info("\nProgrammable counter results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
            print_all_measurement_results(measurement_results_base, n_used_counters);
            pr_info("Programmable counter results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
            print_all_measurement_results(measurement_results, n_used_counters);
        }

        for (size_t c=0; c < n_used_counters; c++) {
            if (pfc_descriptions[c]) seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), pfc_descriptions[c], c));
        }
    }

    /*********************************
     * MSRs.
     ********************************/

    if (no_mem) {
        measurement_template = (char*)&measurement_RDMSR_template_noMem;
    } else {
        measurement_template = (char*)&measurement_RDMSR_template;
    }

    for (size_t i=0; i<n_msr_configs; i++) {
        configure_MSRs(msr_configs[i]);

        run_experiment(measurement_template, measurement_results_base, 1, base_unroll_count, base_loop_count);
        run_experiment(measurement_template, measurement_results, 1, main_unroll_count, main_loop_count);

        if (verbose) {
            pr_info("\nMSR results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
            print_all_measurement_results(measurement_results_base, 1);
            pr_info("MSR results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
            print_all_measurement_results(measurement_results, 1);
        }

        seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), msr_configs[i].description, 0));
    }

    restore_interrupts_preemption();
    kernel_fpu_end();
    return 0;
}

// Unlike with run_experiment(), create_runtime_code() needs to be called before calling run_experiment_with_freeze_on_PMI().
// If n_used_counters is > 0, the programmable counters from 0 to n_used_counters-1 are read; otherwise, the fixed counters are read.
// pmi_counter: 0-2: fixed counters, 3-n: programmable counters
// pmi_counter_val: value that is written to pmi_counter before each measurement
static void run_experiment_with_freeze_on_PMI(int64_t* results[], int n_used_counters, int pmi_counter, uint64_t pmi_counter_val) {
    if (pmi_counter <= 2) {
        set_bit_in_msr(MSR_IA32_FIXED_CTR_CTRL, pmi_counter*4 + 3);
    } else {
        set_bit_in_msr(MSR_IA32_PERFEVTSEL0 + (pmi_counter - 3), 20);
    }

    for (long ri=-warm_up_count; ri<n_measurements; ri++) {
        disable_perf_ctrs_globally();
        clear_perf_counters();
        clear_overflow_status_bits();

        if (pmi_counter <= 2) {
            write_msr(MSR_IA32_FIXED_CTR0 + pmi_counter, pmi_counter_val);
        } else {
            write_msr(MSR_IA32_PMC0 + (pmi_counter - 3), pmi_counter_val);
        }

        ((void(*)(void))runtime_code)();

        if (n_used_counters > 0) {
            for (int c=0; c<n_used_counters; c++) {
                results[c][max(0L, ri)] = read_pmc(c);
            }
        } else {
            for (int c=0; c<3; c++) {
                results[c][max(0L, ri)] = read_pmc(0x40000000 + c);
            }
        }
    }

    if (pmi_counter <= 2) {
        clear_bit_in_msr(MSR_IA32_FIXED_CTR_CTRL, pmi_counter*4 + 3);
    } else {
        clear_bit_in_msr(MSR_IA32_PERFEVTSEL0 + (pmi_counter - 3), 20);
    }
}

static uint64_t get_max_FF_ctr_value(void) {
    return ((uint64_t)1 << Intel_FF_ctr_width) - 1;
}

static uint64_t get_max_programmable_ctr_value(void) {
    return ((uint64_t)1 << Intel_programmable_ctr_width) - 1;
}

static uint64_t get_end_to_end_cycles(void) {
    run_experiment_with_freeze_on_PMI(measurement_results, 0, 0, 0);
    uint64_t cycles = get_aggregate_value(measurement_results[FIXED_CTR_CORE_CYCLES], n_measurements, 1);
    print_verbose("End-to-end cycles: %llu\n", cycles);
    return cycles;
}

static uint64_t get_end_to_end_retired(void) {
    run_experiment_with_freeze_on_PMI(measurement_results, 0, 0, 0);
    uint64_t retired = get_aggregate_value(measurement_results[FIXED_CTR_INST_RETIRED], n_measurements, 1);
    print_verbose("End-to-end retired instructions: %llu\n", retired);
    return retired;
}

// Returns the cycle with which the fixed cycle counter has to be programmed such that the programmable counters are frozen immediately after retiring the last
// instruction of the benchmark (if include_lfence is true, after retiring the lfence instruction that follows the code of the benchmark).
static uint64_t get_cycle_last_retired(bool include_lfence) {
    uint64_t perfevtsel2 = (uint64_t)0xC0 | (1ULL << 17) | (1ULL << 22); // Instructions retired
    // we use counter 2 here, because the counters 0 and 1 do not freeze at the same time on some microarchitectures
    write_msr(MSR_IA32_PERFEVTSEL0+2, perfevtsel2);

    uint64_t last_applicable_instr = get_end_to_end_retired() - 258 + include_lfence;

    run_experiment_with_freeze_on_PMI(measurement_results, 0, 3 + 2, get_max_programmable_ctr_value() - last_applicable_instr);
    uint64_t time_to_last_retired = get_aggregate_value(measurement_results[1], n_measurements, 1);

    // The counters freeze a few cycles after an overflow happens; additionally the programmable and fixed counters do not freeze (or do not start) at exactly
    // the same time. In the following, we search for the value that we have to write to the fixed counter such that the programmable counters stop immediately
    // after the last applicable instruction is retired.
    uint64_t cycle_last_retired = 0;
    for (int64_t cycle=time_to_last_retired; cycle>=0; cycle--) {
        run_experiment_with_freeze_on_PMI(measurement_results, 3, FIXED_CTR_CORE_CYCLES, get_max_FF_ctr_value() - cycle);
        if (get_aggregate_value(measurement_results[2], n_measurements, 1) < last_applicable_instr) {
            cycle_last_retired = cycle+1;
            break;
        }
    }
    print_verbose("Last instruction of benchmark retired in cycle: %llu\n", cycle_last_retired);
    return cycle_last_retired;
}

// Returns the cycle with which the fixed cycle counter has to be programmed such that the programmable counters are frozen in the cycle in which the first
// instruction of the benchmark is added to the IDQ.
static uint64_t get_cycle_first_added_to_IDQ(uint64_t cycle_last_retired_empty) {
    uint64_t perfevtsel2 = (uint64_t)0x79 | ((uint64_t)0x04 << 8) | (1ULL << 22) | (1ULL << 17); // IDQ.MITE_UOPS
    write_msr(MSR_IA32_PERFEVTSEL0+2, perfevtsel2);

    uint64_t cycle_first_added_to_IDQ = 0;
    uint64_t prev_uops = 0;
    for (int64_t cycle=cycle_last_retired_empty-3; cycle>=0; cycle--) {
        run_experiment_with_freeze_on_PMI(measurement_results, 3, FIXED_CTR_CORE_CYCLES, get_max_FF_ctr_value() - cycle);
        uint64_t uops = get_aggregate_value(measurement_results[2], n_measurements, 1);

        if ((prev_uops != 0) && (prev_uops - uops > 1)) {
            cycle_first_added_to_IDQ = cycle + 1;
            break;
        }
        prev_uops = uops;
    }
    print_verbose("First instruction added to IDQ in cycle: %llu\n", cycle_first_added_to_IDQ);
    return cycle_first_added_to_IDQ;
}

// Programs the fixed cycle counter such that it overflows in the specified cycle, runs the benchmark,
// and stores the measurements of the programmable counters in results.
static void perform_measurements_for_cycle(uint64_t cycle, uint64_t* results) {
    // on several microarchitectures, the counters 0 or 1 do not freeze at the same time as the other counters
    int avoid_counters = 0;
    if (displ_model == 0x97) { // Alder Lake
        avoid_counters = (1 << 0);
    } else if ((Intel_perf_mon_ver >= 3) && (Intel_perf_mon_ver <= 4) && (displ_model >= 0x3A)) {
        avoid_counters = (1 << 1);
    }

    // the higher counters don't count some of the events properly (e.g., D1.01 on RKL)
    int n_used_counters = 4;

    size_t next_pfc_config = 0;
    while (next_pfc_config < n_pfc_configs) {
        size_t cur_pfc_config = next_pfc_config;
        char* pfc_descriptions[MAX_PROGRAMMABLE_COUNTERS] = {0};
        next_pfc_config = configure_perf_ctrs_programmable(next_pfc_config, true, true, n_used_counters, avoid_counters, pfc_descriptions);

        run_experiment_with_freeze_on_PMI(measurement_results, n_used_counters, FIXED_CTR_CORE_CYCLES, get_max_FF_ctr_value() - cycle);

        for (size_t c=0; c<n_used_counters; c++) {
            if (pfc_descriptions[c]) {
                results[cur_pfc_config] = get_aggregate_value(measurement_results[c], n_measurements, 1);
                cur_pfc_config++;
            }
        }
    }
}

static int run_nanoBench_cycle_by_cycle(struct seq_file *m, void *v) {
    if (is_AMD_CPU) {
        pr_err("Cycle-by-cycle measurements are not supported on AMD CPUs\n");
        return -1;
    }
    if (n_programmable_counters < 4) {
        pr_err("Cycle-by-cycle measurements require at least four programmable counters\n");
        return -1;
    }
    if (!check_memory_allocations()) {
        return -1;
    }

    kernel_fpu_begin();
    disable_interrupts_preemption();

    clear_perf_counter_configurations();
    enable_freeze_on_PMI();
    configure_perf_ctrs_FF_Intel(0, 1);

    char* measurement_template;
    if (no_mem) {
        measurement_template = (char*)&measurement_cycleByCycle_template_Intel_noMem;
    } else {
        measurement_template = (char*)&measurement_cycleByCycle_template_Intel;
    }

    create_runtime_code(measurement_template, 0, 0); // empty benchmark

    uint64_t cycle_last_retired_empty = get_cycle_last_retired(false);
    uint64_t* results_empty = vmalloc(sizeof(uint64_t[n_pfc_configs]));
    perform_measurements_for_cycle(cycle_last_retired_empty, results_empty);


    uint64_t cycle_last_retired_empty_with_lfence = get_cycle_last_retired(true);
    uint64_t* results_empty_with_lfence = vmalloc(sizeof(uint64_t[n_pfc_configs]));
    perform_measurements_for_cycle(cycle_last_retired_empty_with_lfence, results_empty_with_lfence);

    uint64_t first_cycle = 0;
    uint64_t last_cycle = 0;

    if (!end_to_end) {
        first_cycle = get_cycle_first_added_to_IDQ(cycle_last_retired_empty);
    }

    create_runtime_code(measurement_template, unroll_count, loop_count);

    if (end_to_end) {
        last_cycle = get_end_to_end_cycles();
    } else {
        // Here, we take the cycle after retiring the lfence instruction because some uops of the lfence might retire in the same cycle
        // as the last instruction of the benchmark; this way it is easier to determine the correct count for the number of retired uops.
        last_cycle = get_cycle_last_retired(true);
    }

    uint64_t (*results)[n_pfc_configs] = vmalloc(sizeof(uint64_t[last_cycle+1][n_pfc_configs]));

    for (uint64_t cycle=first_cycle; cycle<=last_cycle; cycle++) {
        perform_measurements_for_cycle(cycle, results[cycle]);
    }

    disable_perf_ctrs_globally();
    disable_freeze_on_PMI();
    clear_overflow_status_bits();
    clear_perf_counter_configurations();

    restore_interrupts_preemption();
    kernel_fpu_end();

    for (size_t i=0; i<n_pfc_configs; i++) {
        seq_printf(m, "%s", pfc_configs[i].description);
        seq_printf(m, ",%lld", results_empty[i]);
        seq_printf(m, ",%lld", results_empty_with_lfence[i]);
        for (long cycle=first_cycle; cycle<=last_cycle; cycle++) {
            seq_printf(m, ",%lld", results[cycle][i]);
        }
        seq_printf(m, "\n");
    }

    vfree(results_empty);
    vfree(results_empty_with_lfence);
    vfree(results);
    return 0;
}

static int open_nanoBench(struct inode *inode, struct file *file) {
    return single_open_size(file, run_nanoBench, NULL, (n_pfc_configs + n_msr_configs + 4*use_fixed_counters) * 128);
}

static int open_nanoBenchCycleByCycle(struct inode *inode, struct file *file) {
    return single_open_size(file, run_nanoBench_cycle_by_cycle, NULL, n_pfc_configs * 4096);
}

// in kernel 5.6, the struct for fileops has changed
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops proc_file_fops_nanoBench = {
    .proc_lseek = seq_lseek,
    .proc_open = open_nanoBench,
    .proc_read = seq_read,
    .proc_release = single_release,
};
static const struct proc_ops proc_file_fops_nanoBenchCycleByCycle = {
    .proc_lseek = seq_lseek,
    .proc_open = open_nanoBenchCycleByCycle,
    .proc_read = seq_read,
    .proc_release = single_release,
};
#else
static const struct file_operations proc_file_fops_nanoBench = {
    .llseek = seq_lseek,
    .open = open_nanoBench,
    .owner = THIS_MODULE,
    .read = seq_read,
    .release = single_release,
};
static const struct file_operations proc_file_fops_nanoBenchCycleByCycle = {
    .llseek = seq_lseek,
    .open = open_nanoBenchCycleByCycle,
    .owner = THIS_MODULE,
    .read = seq_read,
    .release = single_release,
};
#endif

static struct kobject* nb_kobject;

static int __init nb_init(void) {
    pr_info("Initializing nanoBench kernel module...\n");
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    set_memory_x = (void*)kallsyms_lookup_name("set_memory_x");
    set_memory_nx = (void*)kallsyms_lookup_name("set_memory_nx");
    #endif
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    kallsym__vmalloc_node_range = (void*)kallsyms_lookup_name("__vmalloc_node_range");
    #endif
    if (check_cpuid()) {
        return -1;
    }

    for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
        measurement_results[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
        measurement_results_base[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
        if (!measurement_results[i] || !measurement_results_base[i]) {
            pr_err("Could not allocate memory for measurement_results\n");
            return -1;
        }
        memset(measurement_results[i], 0, n_measurements*sizeof(int64_t));
        memset(measurement_results_base[i], 0, n_measurements*sizeof(int64_t));
    }

    // vmalloc addresses are page aligned
    runtime_r14 = vmalloc(RUNTIME_R_SIZE);
    runtime_rbp = vmalloc(RUNTIME_R_SIZE);
    runtime_rdi = vmalloc(RUNTIME_R_SIZE);
    runtime_rsi = vmalloc(RUNTIME_R_SIZE);
    runtime_rsp = vmalloc(RUNTIME_R_SIZE);
    if (!runtime_r14 || !runtime_rbp || !runtime_rdi || !runtime_rsi || !runtime_rsp) {
        pr_err("Could not allocate memory for runtime_r*\n");
        return -1;
    }
    memset(runtime_r14, 0, RUNTIME_R_SIZE);
    memset(runtime_rbp, 0, RUNTIME_R_SIZE);
    memset(runtime_rdi, 0, RUNTIME_R_SIZE);
    memset(runtime_rsi, 0, RUNTIME_R_SIZE);
    memset(runtime_rsp, 0, RUNTIME_R_SIZE);
    runtime_r14 += RUNTIME_R_SIZE/2;
    runtime_rbp += RUNTIME_R_SIZE/2;
    runtime_rdi += RUNTIME_R_SIZE/2;
    runtime_rsi += RUNTIME_R_SIZE/2;
    runtime_rsp += RUNTIME_R_SIZE/2;

    runtime_code_base = kmalloc(KMALLOC_MAX, GFP_KERNEL);
    if (!runtime_code_base) {
        pr_err("Could not allocate memory for runtime_code\n");
        return -1;
    }
    runtime_code_base_memory_size = KMALLOC_MAX;
    set_memory_x((unsigned long)runtime_code_base, runtime_code_base_memory_size/PAGE_SIZE);
    runtime_code = runtime_code_base;

    nb_kobject = kobject_create_and_add("nb", kernel_kobj->parent);
    if (!nb_kobject) {
        pr_err("failed to create and add nb\n");
        return -1;
    }

    int error = sysfs_create_file(nb_kobject, &clear_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &reset_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_init_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_late_init_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_one_time_init_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &config_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &msr_config_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &fixed_counters_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &loop_count_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &unroll_count_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &n_measurements_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &warm_up_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &initial_warm_up_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &alignment_offset_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &end_to_end_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &drain_frontend_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &agg_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &basic_mode_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &no_mem_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &no_normalization_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &r14_size_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &print_r14_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_offset_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &addresses_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &verbose_attribute.attr);

    if (error) {
        pr_err("failed to create file in /sys/nb/\n");
        return error;
    }

    struct proc_dir_entry* proc_file_entry = proc_create("nanoBench", 0, NULL, &proc_file_fops_nanoBench);
    struct proc_dir_entry* proc_file_entry2 = proc_create("nanoBenchCycleByCycle", 0, NULL, &proc_file_fops_nanoBenchCycleByCycle);
    if(proc_file_entry == NULL || proc_file_entry2 == NULL) {
        pr_err("failed to create file in /proc/\n");
        return -1;
    }

    return 0;
}

static void __exit nb_exit(void) {
    kfree(code);
    kfree(code_init);
    kfree(code_late_init);
    kfree(code_one_time_init);
    kfree(pfc_config_file_content);
    kfree(msr_config_file_content);
    vfree(runtime_one_time_init_code);
    vfree(runtime_rbp - RUNTIME_R_SIZE/2);
    vfree(runtime_rdi - RUNTIME_R_SIZE/2);
    vfree(runtime_rsi - RUNTIME_R_SIZE/2);
    vfree(runtime_rsp - RUNTIME_R_SIZE/2);

    if (runtime_code_base) {
        set_memory_nx((unsigned long)runtime_code_base, runtime_code_base_memory_size/PAGE_SIZE);
        kfree(runtime_code_base);
    }

    if (n_r14_segments > 0) {
        for (int i=0; i<n_r14_segments; i++) {
            kfree(r14_segments[i]);
        }
    } else {
        vfree(runtime_r14 - RUNTIME_R_SIZE/2);
    }

    for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
        kfree(measurement_results[i]);
        kfree(measurement_results_base[i]);
    }

    kobject_put(nb_kobject);
    remove_proc_entry("nanoBench", NULL);
    remove_proc_entry("nanoBenchCycleByCycle", NULL);
}

module_init(nb_init);
module_exit(nb_exit);

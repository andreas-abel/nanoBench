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

// 4 Mb is the maximum that kmalloc supports on my machines
#define KMALLOC_MAX (4*1024*1024)

char* runtime_code_base = NULL;

size_t code_offset = 0;
size_t code_memory_size = 0;
size_t code_init_memory_size = 0;
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
        pr_debug("Error opening file %s\n", file_name);
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
        pr_debug("Error getting file attributes\n");
        return -1;
    }

    size_t file_size = ks.size;
    *buf_len = file_size;

    if (file_size + 1 > *buf_memory_size) {
        kfree(*buf);
        *buf_memory_size = max(2*(file_size + 1), PAGE_SIZE);
        *buf = kmalloc(*buf_memory_size, GFP_KERNEL);
        if (!*buf) {
            printk(KERN_ERR "Could not allocate memory for %s\n", file_name);
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

static ssize_t one_time_init_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return 0;
}
static ssize_t one_time_init_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    read_file_into_buffer(buf, &code_one_time_init, &code_one_time_init_length, &code_one_time_init_memory_size);
    size_t new_runtime_one_time_init_code_memory_size = 10000 + code_one_time_init_memory_size;
    if (new_runtime_one_time_init_code_memory_size > runtime_one_time_init_code_memory_size) {
        runtime_one_time_init_code_memory_size = new_runtime_one_time_init_code_memory_size;
        vfree(runtime_one_time_init_code);
        runtime_one_time_init_code = __vmalloc(runtime_one_time_init_code_memory_size, GFP_KERNEL, PAGE_KERNEL_EXEC);
        if (!runtime_one_time_init_code) {
            runtime_one_time_init_code_memory_size = 0;
            pr_debug("failed to allocate executable memory\n");
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
                printk(KERN_ERR "Could not allocate memory for measurement_results\n");
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

static ssize_t basic_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%u\n", basic_mode);
}
static ssize_t basic_mode_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%u", &basic_mode);
    return count;
}
static struct kobj_attribute basic_mode_attribute =__ATTR(basic_mode, 0660, basic_mode_show, basic_mode_store);

static ssize_t no_mem_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%u\n", no_mem);
}
static ssize_t no_mem_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%u", &no_mem);
    return count;
}
static struct kobj_attribute no_mem_attribute =__ATTR(no_mem, 0660, no_mem_show, no_mem_store);

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
            pr_debug("No physically contiguous memory area of the requested size found.\n");
            pr_debug("Try rebooting your computer.\n");
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
    return count;
}
static struct kobj_attribute code_offset_attribute =__ATTR(code_offset, 0660, code_offset_show, code_offset_store);

static ssize_t verbose_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%u\n", verbose);
}
static ssize_t verbose_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%u", &verbose);
    return count;
}
static struct kobj_attribute verbose_attribute =__ATTR(verbose, 0660, verbose_show, verbose_store);

static ssize_t clear_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    code_init_length = 0;
    code_length = 0;
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
    basic_mode = BASIC_MODE_DEFAULT;
    aggregate_function = AGGREGATE_FUNCTION_DEFAULT;
    verbose = VERBOSE_DEFAULT;

    code_init_length = 0;
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

static int show(struct seq_file *m, void *v) {
    for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
        if (!measurement_results[i] || !measurement_results_base[i]) {
            printk(KERN_ERR "Could not allocate memory for measurement_results\n");
            return -1;
        }
    }

    size_t req_code_length = code_offset + get_required_runtime_code_length();
    if (req_code_length > runtime_code_base_memory_size) {
        printk(KERN_ERR "Maximum supported code size %zu kB; requested %zu kB\n", runtime_code_base_memory_size/1024, req_code_length/1024);
        return -1;
    }
    runtime_code = runtime_code_base + code_offset;

    kernel_fpu_begin();

    long base_unroll_count = (basic_mode?0:unroll_count);
    long main_unroll_count = (basic_mode?unroll_count:2*unroll_count);
    long base_loop_count = (basic_mode?0:loop_count);
    long main_loop_count = loop_count;

    char buf[100];
    char* measurement_template;

    /*********************************
     * Fixed-function counters.
     ********************************/
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

    configure_perf_ctrs_FF(0, 1);
    create_and_run_one_time_init_code();
    run_warmup_experiment(measurement_template);

    if (is_AMD_CPU) {
        run_experiment(measurement_template, measurement_results_base, 3, base_unroll_count, base_loop_count);
        run_experiment(measurement_template, measurement_results, 3, main_unroll_count, main_loop_count);

        if (verbose) {
            pr_debug("\nRDTSC, MPERF, and APERF results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
            print_all_measurement_results(measurement_results_base, 3);
            pr_debug("RDTSC, MPERF, and and APERF results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
            print_all_measurement_results(measurement_results, 3);
        }

        seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "RDTSC", 0));
        seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "MPERF", 1));
        seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "APERF", 2));
    } else {
        run_experiment(measurement_template, measurement_results_base, 4, base_unroll_count, base_loop_count);
        run_experiment(measurement_template, measurement_results, 4, main_unroll_count, main_loop_count);

        if (verbose) {
            pr_debug("\nRDTSC and fixed-function counter results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
            print_all_measurement_results(measurement_results_base, 4);
            pr_debug("RDTSC and fixed-function counter results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
            print_all_measurement_results(measurement_results, 4);
        }

        seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "RDTSC", 0));
        seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "Instructions retired", 1));
        seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "Core cycles", 2));
        seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), "Reference cycles", 3));
    }

    /*********************************
     * Programmable counters.
     ********************************/
    if (is_AMD_CPU) {
        if (no_mem) {
            measurement_template = (char*)&measurement_template_AMD_noMem;
        } else {
            measurement_template = (char*)&measurement_template_AMD;
        }
    } else {
        if (no_mem) {
            if (n_programmable_counters >= 4) {
                measurement_template = (char*)&measurement_template_Intel_noMem_4;
            } else {
                measurement_template = (char*)&measurement_template_Intel_noMem_2;
            }
        } else {
            if (n_programmable_counters >= 4) {
                measurement_template = (char*)&measurement_template_Intel_4;
            } else {
                measurement_template = (char*)&measurement_template_Intel_2;
            }
        }
    }

    for (size_t i=0; i<n_pfc_configs; i+=n_programmable_counters) {
        configure_perf_ctrs_programmable(i, min(i+n_programmable_counters, n_pfc_configs), 1, 1);
        // on some microarchitectures (e.g., Broadwell), some events (e.g., L1 misses) are not counted properly if only the OS field is set

        run_experiment(measurement_template, measurement_results_base, n_programmable_counters, base_unroll_count, base_loop_count);
        run_experiment(measurement_template, measurement_results, n_programmable_counters, main_unroll_count, main_loop_count);

        if (verbose) {
            pr_debug("\nProgrammable counter results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
            print_all_measurement_results(measurement_results_base, n_programmable_counters);
            pr_debug("Programmable counter results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
            print_all_measurement_results(measurement_results, n_programmable_counters);
        }

        for (int c=0; c < n_programmable_counters && i + c < n_pfc_configs; c++) {
            if (!pfc_configs[i+c].invalid) seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), pfc_configs[i+c].description, c));
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
            pr_debug("\nMSR results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
            print_all_measurement_results(measurement_results_base, 1);
            pr_debug("MSR results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
            print_all_measurement_results(measurement_results, 1);
        }

        seq_printf(m, "%s", compute_result_str(buf, sizeof(buf), msr_configs[i].description, 0));
    }

    kernel_fpu_end();
    return 0;
}

static int open(struct inode *inode, struct  file *file) {
    return single_open(file, show, NULL);
}

static const struct file_operations proc_file_fops = {
    .llseek = seq_lseek,
    .open = open,
    .owner = THIS_MODULE,
    .read = seq_read,
    .release = single_release,
};

static struct kobject* nb_kobject;

static int __init nb_init(void) {
    pr_debug("Initializing nanoBench kernel module...\n");
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    set_memory_x = (void*)kallsyms_lookup_name("set_memory_x");
    set_memory_nx = (void*)kallsyms_lookup_name("set_memory_nx");
    #endif
    if (check_cpuid()) {
        return -1;
    }

    for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
        measurement_results[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
        measurement_results_base[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
        if (!measurement_results[i] || !measurement_results_base[i]) {
            printk(KERN_ERR "Could not allocate memory for measurement_results\n");
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
        printk(KERN_ERR "Could not allocate memory for runtime_r*\n");
        return -1;
    }
    runtime_r14 += RUNTIME_R_SIZE/2;
    runtime_rbp += RUNTIME_R_SIZE/2;
    runtime_rdi += RUNTIME_R_SIZE/2;
    runtime_rsi += RUNTIME_R_SIZE/2;
    runtime_rsp += RUNTIME_R_SIZE/2;

    runtime_code_base = kmalloc(KMALLOC_MAX, GFP_KERNEL);
    if (!runtime_code_base) {
        printk(KERN_ERR "Could not allocate memory for runtime_code\n");
        return -1;
    }
    runtime_code_base_memory_size = KMALLOC_MAX;
    set_memory_x((unsigned long)runtime_code_base, runtime_code_base_memory_size/PAGE_SIZE);
    runtime_code = runtime_code_base;

    nb_kobject = kobject_create_and_add("nb", kernel_kobj->parent);
    if (!nb_kobject) {
        pr_debug("failed to create and add nb\n");
        return -1;
    }

    int error = sysfs_create_file(nb_kobject, &clear_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &reset_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_init_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_one_time_init_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &config_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &msr_config_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &loop_count_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &unroll_count_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &n_measurements_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &warm_up_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &initial_warm_up_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &alignment_offset_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &agg_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &basic_mode_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &no_mem_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &r14_size_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &print_r14_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_offset_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &verbose_attribute.attr);

    if (error) {
        pr_debug("failed to create file in /sys/nb/\n");
        return error;
    }

    struct proc_dir_entry* proc_file_entry = proc_create("nanoBench", 0, NULL, &proc_file_fops);
    if(proc_file_entry == NULL) {
        pr_debug("failed to create file in /proc/\n");
        return -1;
    }

    return 0;
}

static void __exit nb_exit(void) {
    kfree(code);
    kfree(code_init);
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
}

module_init(nb_init);
module_exit(nb_exit);

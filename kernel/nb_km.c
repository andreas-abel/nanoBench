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
#include <../arch/x86/include/asm/fpu/api.h>

#include "../common/nanoBench.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andreas Abel");

static ssize_t init_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    memcpy(buf, code_init, code_init_length);
    return code_init_length;
}
static ssize_t init_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    memcpy(code_init, buf, count);
    code_init_length = count;
    return count;
}
static struct kobj_attribute code_init_attribute =__ATTR(init, 0660, init_show, init_store);

static ssize_t code_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    memcpy(buf, code, code_length);
    return code_length;
}
static ssize_t code_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    memcpy(code, buf, count);
    code_length = count;
    return count;
}
static struct kobj_attribute code_attribute =__ATTR(code, 0660, code_show, code_store);

static ssize_t config_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    ssize_t count = 0;
    for (int i=0; i<n_pfc_configs; i++) {
        if (is_Intel_CPU) {
            count += sprintf(&(buf[count]), "%02lx.%02lx %s\n", pfc_configs[i].evt_num, pfc_configs[i].umask, pfc_configs[i].description);
        } else {
            count += sprintf(&(buf[count]), "%03lx.%02lx %s\n", pfc_configs[i].evt_num, pfc_configs[i].umask, pfc_configs[i].description);
        }
    }
    return count;
}
static ssize_t config_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    memcpy(pfc_config_file_content, buf, count);
    pfc_config_file_content[count] = '\0';
    parse_counter_configs();
    return count;
}
static struct kobj_attribute config_attribute =__ATTR(config, 0660, config_show, config_store);

static ssize_t unroll_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", unroll_count);
}
static ssize_t unroll_count_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    long old_unroll_count = unroll_count;
    sscanf(buf, "%ld", &unroll_count);

    if (old_unroll_count != unroll_count) {
        vfree(runtime_code);
        runtime_code = __vmalloc(PAGE_SIZE + (unroll_count)*PAGE_SIZE*2 + 10000, GFP_KERNEL, PAGE_KERNEL_EXEC);
        if (!runtime_code) {
            pr_debug("failed to allocate executable memory\n");
        }
    }
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

    if (old_n_measurements != n_measurements) {
        for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
            kfree(measurement_results[i]);
            kfree(measurement_results_base[i]);
            measurement_results[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
            measurement_results_base[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
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
    } else if (!strncmp(buf, "med", 3)) {
        aggregate_function = MED;
    } else {
        aggregate_function = AVG_20_80;
    }
    return count;
}
static struct kobj_attribute agg_attribute =__ATTR(agg, 0660, agg_show, agg_store);

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
    n_pfc_configs = 0;

    return 0;
}
static ssize_t reset_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    return 0;
}
static struct kobj_attribute reset_attribute =__ATTR(reset, 0660, reset_show, reset_store);

static ssize_t run_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    kernel_fpu_begin();

    long base_unroll_count = (basic_mode?0:unroll_count);
    long main_unroll_count = (basic_mode?unroll_count:2*unroll_count);
    long base_loop_count = (basic_mode?0:loop_count);
    long main_loop_count = loop_count;

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

        compute_result_str(buf+strlen(buf), PAGE_SIZE-strlen(buf), "RDTSC", 0);
        compute_result_str(buf+strlen(buf), PAGE_SIZE-strlen(buf), "MPERF", 1);
        compute_result_str(buf+strlen(buf), PAGE_SIZE-strlen(buf), "APERF", 2);
    } else {
        run_experiment(measurement_template, measurement_results_base, 4, base_unroll_count, base_loop_count);
        run_experiment(measurement_template, measurement_results, 4, main_unroll_count, main_loop_count);

        if (verbose) {
            pr_debug("\nRDTSC and fixed-function counter results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
            print_all_measurement_results(measurement_results_base, 4);
            pr_debug("RDTSC and fixed-function counter results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
            print_all_measurement_results(measurement_results, 4);
        }

        compute_result_str(buf+strlen(buf), PAGE_SIZE-strlen(buf), "RDTSC", 0);
        compute_result_str(buf+strlen(buf), PAGE_SIZE-strlen(buf), "Instructions retired", 1);
        compute_result_str(buf+strlen(buf), PAGE_SIZE-strlen(buf), "Core cycles", 2);
        compute_result_str(buf+strlen(buf), PAGE_SIZE-strlen(buf), "Reference cycles", 3);
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
            measurement_template = (char*)&measurement_template_Intel_noMem;
        } else {
            measurement_template = (char*)&measurement_template_Intel;
        }
    }

    for (size_t i=0; i<n_pfc_configs; i+=n_programmable_counters) {
        configure_perf_ctrs_programmable(i, min(i+n_programmable_counters, n_pfc_configs), 0, 1);

        run_experiment(measurement_template, measurement_results_base, n_programmable_counters, base_unroll_count, base_loop_count);
        run_experiment(measurement_template, measurement_results, n_programmable_counters, main_unroll_count, main_loop_count);

        if (verbose) {
            pr_debug("\nProgrammable counter results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
            print_all_measurement_results(measurement_results_base, n_programmable_counters);
            pr_debug("Programmable counter results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
            print_all_measurement_results(measurement_results, n_programmable_counters);
        }

        for (int c=0; c < n_programmable_counters && i + c < n_pfc_configs; c++) {
            if (!pfc_configs[i+c].invalid) compute_result_str(buf+strlen(buf), PAGE_SIZE-strlen(buf), pfc_configs[i+c].description, c);
        }
    }

    kernel_fpu_end();

    return strlen(buf);
}
static ssize_t run_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    return 0;
}
static struct kobj_attribute run_attribute =__ATTR(run, 0660, run_show, run_store);

static struct kobject* nb_kobject;

static int __init nb_init (void) {
    pr_debug("Initializing nanoBench kernel module...\n");

    if (check_cpuid()) {
        return -1;
    }

    code = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!code) {
        printk(KERN_ERR "Could not allocate memory for code\n");
        return -1;
    }

    code_init = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!code_init) {
        printk(KERN_ERR "Could not allocate memory for code_init\n");
        return -1;
    }

    pfc_config_file_content = kmalloc(PAGE_SIZE+1, GFP_KERNEL);
    if (!pfc_config_file_content) {
        printk(KERN_ERR "Could not allocate memory for pfc_config_file_content\n");
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

    runtime_code = __vmalloc(PAGE_SIZE + (unroll_count)*PAGE_SIZE*2 + 10000, GFP_KERNEL, PAGE_KERNEL_EXEC);
    if (!runtime_code) {
        pr_debug("failed to allocate executable memory\n");
        return -1;
    }

    nb_kobject = kobject_create_and_add("nb", kernel_kobj->parent);
    if (!nb_kobject) {
        pr_debug("failed to create and add nb\n");
        return -1;
    }

    int error = sysfs_create_file(nb_kobject, &run_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &clear_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &reset_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_init_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &config_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &loop_count_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &unroll_count_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &n_measurements_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &warm_up_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &initial_warm_up_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &agg_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &basic_mode_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &no_mem_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &verbose_attribute.attr);

    if (error) {
        pr_debug("failed to create file in /sys/nb/\n");
        return error;
    }

    return 0;
}

static void __exit nb_exit (void) {
    kfree(code);
    kfree(code_init);
    kfree(pfc_config_file_content);
    vfree(runtime_code);
    vfree(runtime_r14);
    vfree(runtime_rbp);
    vfree(runtime_rdi);
    vfree(runtime_rsi);
    vfree(runtime_rsp);

    for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
        kfree(measurement_results[i]);
        kfree(measurement_results_base[i]);
    }

    kobject_put(nb_kobject);
}

module_init(nb_init);
module_exit(nb_exit);

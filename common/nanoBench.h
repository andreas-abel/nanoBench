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

#ifndef NANOBENCH_H
#define NANOBENCH_H

#ifdef __KERNEL__
    #include <linux/module.h>
    #include <linux/sort.h>
#else
    #include <inttypes.h>
    #include <stddef.h>
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
#endif

#include <cpuid.h>

#ifdef __KERNEL__
    #define print_error(...) pr_debug(__VA_ARGS__)
    #define print_verbose(...) if (verbose) pr_debug(__VA_ARGS__)
    #define print_user_verbose(...) pr_debug(__VA_ARGS__)
    #define nb_strtoul(s, base, res) kstrtoul(s, base, res)
    #define qsort(base, n, size, comp) sort(base, n, size, comp, NULL)
#else
    #define print_error(...) fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");
    #define print_verbose(...) if (verbose) printf(__VA_ARGS__);
    #define print_user_verbose(...) if (verbose) printf(__VA_ARGS__);
    #define nb_strtoul(s, base, res) *res = strtoul(s, NULL, base)
#endif

#ifndef MSR_IA32_PMC0
#define MSR_IA32_PMC0               0x0C1
#endif
#ifndef MSR_IA32_PERFEVTSEL0
#define MSR_IA32_PERFEVTSEL0        0x186
#endif
#ifndef MSR_OFFCORE_RSP0
#define MSR_OFFCORE_RSP0            0x1A6
#endif
#ifndef MSR_OFFCORE_RSP1
#define MSR_OFFCORE_RSP1            0x1A7
#endif
#ifndef MSR_IA32_FIXED_CTR0
#define MSR_IA32_FIXED_CTR0         0x309
#endif
#ifndef MSR_IA32_FIXED_CTR_CTRL
#define MSR_IA32_FIXED_CTR_CTRL     0x38D
#endif
#ifndef MSR_IA32_PERF_GLOBAL_CTRL
#define MSR_IA32_PERF_GLOBAL_CTRL   0x38F
#endif
#ifndef MSR_PEBS_FRONTEND
#define MSR_PEBS_FRONTEND           0x3F7
#endif
#ifndef CORE_X86_MSR_PERF_CTL
#define CORE_X86_MSR_PERF_CTL       0xC0010200
#endif
#ifndef CORE_X86_MSR_PERF_CTR
#define CORE_X86_MSR_PERF_CTR       0xC0010201
#endif


// How often the measurement will be repeated.
extern long n_measurements;
#define N_MEASUREMENTS_DEFAULT 10;

// How often the code to be measured will be unrolled.
extern long unroll_count;
#define UNROLL_COUNT_DEFAULT 1000;

// Number of iterations of the inner loop. Setting this to 0 will disable the inner loop; the code to be measured is then executed unroll_count many times.
extern long loop_count;
#define LOOP_COUNT_DEFAULT 0;

// Number of executions of the measurement code before each sequence of measurement runs.
extern long warm_up_count;
#define WARM_UP_COUNT_DEFAULT 5;

// Number of executions of the measurement code before the first measurement.
extern long initial_warm_up_count;
#define INITIAL_WARM_UP_COUNT_DEFAULT 0;

// By default, the code to be benchmarked is aligned to 64 bytes. This parameter allows to specify an offset to this alignment.
extern size_t alignment_offset;
#define ALIGNMENT_OFFSET_DEFAULT 0;

// If enabled, the front-end buffers are drained between code_late_init and code by executing a sequence of 128 15-Byte NOP instructions.
extern int drain_frontend;
#define DRAIN_FRONTEND_DEFAULT 0;

// If enabled, the temporary performance counter values are stored in registers instead of in memory;
// the code to be measured must then not use registers R8-R13
extern int no_mem;
#define NO_MEM_DEFAULT 0;

// If enabled, the measurement results are not divided by the number of repetitions.
extern int no_normalization;
#define NO_NORMALIZATION_DEFAULT 0;

// If disabled, the first measurement is performed with 2*unroll_count and the second with unroll_count; the reported result is the difference between the two
// measurements.
// If enabled, the first measurement is performed with unroll_count and the second with an empty measurement body; the reported result is the difference
// between the two measurements.
extern int basic_mode;
#define BASIC_MODE_DEFAULT 0;

enum agg_enum {AVG_20_80, MIN, MAX, MED};
extern int aggregate_function;
#define AGGREGATE_FUNCTION_DEFAULT AVG_20_80;

extern int verbose;
#define VERBOSE_DEFAULT 0;

// Whether to generate a breakpoint trap after executing the code to be benchmarked.
extern int debug;
#define DEBUG_DEFAULT 0;

extern char* code;
extern size_t code_length;

extern char* code_init;
extern size_t code_init_length;

extern char* code_late_init;
extern size_t code_late_init_length;

extern char* code_one_time_init;
extern size_t code_one_time_init_length;

struct pfc_config {
    unsigned long evt_num;
    unsigned long umask;
    unsigned long cmask;
    unsigned int any;
    unsigned int edge;
    unsigned int inv;
    unsigned long msr_3f6h;
    unsigned long msr_pf;
    unsigned long msr_rsp0;
    unsigned long msr_rsp1;
    unsigned int invalid;
    char* description;
};
extern struct pfc_config pfc_configs[];
extern size_t n_pfc_configs;
extern char* pfc_config_file_content;

struct msr_config {
    unsigned long rdmsr;
    unsigned long wrmsr[10];
    unsigned long wrmsr_val[10];
    size_t n_wrmsr;
    char* description;
};
extern struct msr_config msr_configs[];
extern size_t n_msr_configs;
extern char* msr_config_file_content;

extern int is_Intel_CPU;
extern int is_AMD_CPU;

#define MAX_PROGRAMMABLE_COUNTERS 6
extern int n_programmable_counters;

// Pointers to a memory regions that are writable and executable.
extern char* runtime_code;
extern char* runtime_one_time_init_code;

#define RUNTIME_R_SIZE (1024*1024)

// During measurements, R14, RBP, RDI, RSI, and RSP will contain these addresses plus RUNTIME_R_SIZE/2.
// If r14_size is set in the kernel module, R14 will not have this offset.
extern void* runtime_r14;
extern void* runtime_rbp;
extern void* runtime_rdi;
extern void* runtime_rsi;
extern void* runtime_rsp;

// Stores performance counter values during measurements.
extern int64_t pfc_mem[MAX_PROGRAMMABLE_COUNTERS];

// Stores the RSP during measurements.
extern void* RSP_mem;

extern int64_t* measurement_results[MAX_PROGRAMMABLE_COUNTERS];
extern int64_t* measurement_results_base[MAX_PROGRAMMABLE_COUNTERS];

// Process should be pinned to this CPU.
extern int cpu;

// Checks whether we have an Intel or AMD CPU and determines the number of programmable counters.
// Returns 0 if successful, 1 otherwise.
int check_cpuid(void);

void parse_counter_configs(void);
void parse_msr_configs(void);

uint64_t read_value_from_cmd(char* cmd);

uint64_t read_msr(unsigned int msr);
void write_msr(unsigned int msr, uint64_t value);

// Enables and clears the fixed-function performance counters.
void configure_perf_ctrs_FF(unsigned int usr, unsigned int os);

// Clears the programmable performance counters and writes the configurations to the corresponding MSRs.
// start and end are indices into the pfc_configs array.
void configure_perf_ctrs_programmable(int start, int end, unsigned int usr, unsigned int os);

void configure_MSRs(struct msr_config config);

size_t get_required_runtime_code_length(void);

void create_runtime_code(char* measurement_template, long local_unroll_count, long local_loop_count);
void run_warmup_experiment(char* measurement_template);
void run_experiment(char* measurement_template, int64_t* results[], int n_counters, long local_unroll_count, long local_loop_count);
void create_and_run_one_time_init_code(void);

char* compute_result_str(char* buf, size_t buf_len, char* desc, int counter);
int64_t get_aggregate_value(int64_t* values, size_t length, size_t scale);
int cmpInt64(const void *a, const void *b);
long long ll_abs(long long val);

void print_all_measurement_results(int64_t* results[], int n_counters);


#define MAGIC_BYTES_INIT 0x10b513b1C2813F04
#define MAGIC_BYTES_CODE 0x20b513b1C2813F04
#define MAGIC_BYTES_RSP_ADDRESS 0x30b513b1C2813F04
#define MAGIC_BYTES_RUNTIME_R14 0x40b513b1C2813F04
#define MAGIC_BYTES_RUNTIME_RBP 0x50b513b1C2813F04
#define MAGIC_BYTES_RUNTIME_RDI 0x60b513b1C2813F04
#define MAGIC_BYTES_RUNTIME_RSI 0x70b513b1C2813F04
#define MAGIC_BYTES_RUNTIME_RSP 0x80b513b1C2813F04
#define MAGIC_BYTES_PFC 0x90b513b1C2813F04
#define MAGIC_BYTES_MSR 0xA0b513b1C2813F04
#define MAGIC_BYTES_TEMPLATE_END 0xB0b513b1C2813F04
#define MAGIC_BYTES_PFC_START 0xC0b513b1C2813F04
#define MAGIC_BYTES_PFC_END 0xD0b513b1C2813F04

#define MAGIC_BYTES_CODE_PFC_START 0xE0b513b1C2813F04
#define MAGIC_BYTES_CODE_PFC_STOP 0xF0b513b1C2813F04


#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

int starts_with_magic_bytes(char* c, int64_t magic_bytes);

// The following functions must not use global variables (or anything that uses RIP-relative addressing)
void measurement_template_Intel_2(void);
void measurement_template_Intel_4(void);
void measurement_template_Intel_noMem_2(void);
void measurement_template_Intel_noMem_4(void);
void measurement_template_AMD(void);
void measurement_template_AMD_noMem(void);
void measurement_FF_template_Intel(void);
void measurement_FF_template_Intel_noMem(void);
void measurement_FF_template_AMD(void);
void measurement_FF_template_AMD_noMem(void);
void measurement_RDTSC_template(void);
void measurement_RDTSC_template_noMem(void);
void measurement_RDMSR_template(void);
void measurement_RDMSR_template_noMem(void);
void one_time_init_template(void);

// RBX, RBP, and R12–R15 are callee saved registers according to the "System V AMD64 ABI" (https://en.wikipedia.org/wiki/X86_calling_conventions)
#define SAVE_REGS_FLAGS()                                 \
    asm volatile(                                         \
        ".intel_syntax noprefix\n"                        \
        "push rbx\n"                                      \
        "push rbp\n"                                      \
        "push r12\n"                                      \
        "push r13\n"                                      \
        "push r14\n"                                      \
        "push r15\n"                                      \
        "pushfq\n"                                        \
        "mov r15, "STRINGIFY(MAGIC_BYTES_RSP_ADDRESS)"\n" \
        "mov [r15], rsp\n"                                \
        "mov rax, 0\n"                                    \
        "mov rbx, 0\n"                                    \
        "mov rcx, 0\n"                                    \
        "mov rdx, 0\n"                                    \
        "mov r8,  0\n"                                    \
        "mov r9,  0\n"                                    \
        "mov r10, 0\n"                                    \
        "mov r11, 0\n"                                    \
        "mov r12, 0\n"                                    \
        "mov r13, 0\n"                                    \
        "mov r15, 0\n"                                    \
        "mov r14, "STRINGIFY(MAGIC_BYTES_RUNTIME_R14)"\n" \
        "mov rbp, "STRINGIFY(MAGIC_BYTES_RUNTIME_RBP)"\n" \
        "mov rdi, "STRINGIFY(MAGIC_BYTES_RUNTIME_RDI)"\n" \
        "mov rsi, "STRINGIFY(MAGIC_BYTES_RUNTIME_RSI)"\n" \
        "mov rsp, "STRINGIFY(MAGIC_BYTES_RUNTIME_RSP)"\n" \
        ".att_syntax noprefix");

#define RESTORE_REGS_FLAGS()                              \
    asm volatile(                                         \
        ".intel_syntax noprefix\n"                        \
        "mov r15, "STRINGIFY(MAGIC_BYTES_RSP_ADDRESS)"\n" \
        "mov rsp, [r15]\n"                                \
        "popfq\n"                                         \
        "pop r15\n"                                       \
        "pop r14\n"                                       \
        "pop r13\n"                                       \
        "pop r12\n"                                       \
        "pop rbp\n"                                       \
        "pop rbx\n"                                       \
        ".att_syntax noprefix");

#endif
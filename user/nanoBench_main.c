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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

#include "../common/nanoBench.h"

void print_usage() {
    printf("\n");
    printf("nanoBench usage:\n");
    printf("\n");
    printf("  -code <filename>:               Binary file containing the code to be benchmarked.\n");
    printf("  -code_init <filename>:          Binary file containing code to be executed once before each measurement.\n");
    printf("  -code_late_init <filename>:     Binary file containing code to be executed once immediately before the code to be benchmarked.\n");
    printf("  -code_one_time_init <filename>: Binary file containing code to be executed once before the first measurement\n");
    printf("  -config <filename>:             File with performance counter event specifications.\n");
    printf("  -n_measurements <n>:            Number of times the measurements are repeated.\n");
    printf("  -unroll_count <n>:              Number of copies of the benchmark code inside the inner loop.\n");
    printf("  -loop_count <n>:                Number of iterations of the inner loop.\n");
    printf("  -warm_up_count <n>:             Number of runs before the first measurement gets recorded.\n");
    printf("  -initial_warm_up_count <n>:     Number of runs before any measurement is performed.\n");
    printf("  -alignment_offset <n>:          Alignment offset.\n");
    printf("  -df:                            Drains front-end buffers between executing code_late_init and code.\n");
    printf("  -avg:                           Selects the arithmetic mean as the aggregate function.\n");
    printf("  -median:                        Selects the median as the aggregate function.\n");
    printf("  -min:                           Selects the minimum as the aggregate function.\n");
    printf("  -basic_mode:                    Enables basic mode.\n");
    printf("  -no_mem:                        The code for reading the perf. ctrs. does not make memory accesses.\n");
    printf("  -no_normalization:              The measurement results are not divided by the number of repetitions.\n");
    printf("  -verbose:                       Outputs the results of all performance counter readings.\n");
    printf("  -cpu <n>:                       Pins the measurement thread to CPU n. \n");
    printf("  -usr <n>:                       If 1, counts events at a privilege level greater than 0.\n");
    printf("  -os <n>:                        If 1, counts events at a privilege level 0.\n");
    printf("  -debug:                         Generate a breakpoint trap after running the code to be benchmarked.\n");
}

size_t mmap_file(char* filename, char** content) {
    int fd = open(filename, O_RDONLY);
    size_t len = lseek(fd, 0, SEEK_END);
    *content = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (*content == MAP_FAILED) {
        fprintf(stderr, "Error reading %s\n", filename);
        exit(1);
    }
    close(fd);
    return len;
}

int main(int argc, char **argv) {
    /*************************************
     * Parse command-line options
     ************************************/
    char* config_file_name = NULL;
    int usr = 1;
    int os = 0;

    struct option long_opts[] = {
        {"code", required_argument, 0, 'c'},
        {"code_init", required_argument, 0, 'i'},
        {"code_late_init", required_argument, 0, 't'},
        {"code_one_time_init", required_argument, 0, 'o'},
        {"config", required_argument, 0, 'f'},
        {"n_measurements", required_argument, 0, 'n'},
        {"unroll_count", required_argument, 0, 'u'},
        {"loop_count", required_argument, 0, 'l'},
        {"warm_up_count", required_argument, 0, 'w'},
        {"initial_warm_up_count", required_argument, 0, 'a'},
        {"alignment_offset", required_argument, 0, 'm'},
        {"df", no_argument, &drain_frontend, 1},
        {"avg", no_argument, &aggregate_function, AVG_20_80},
        {"median", no_argument, &aggregate_function, MED},
        {"min", no_argument, &aggregate_function, MIN},
        {"max", no_argument, &aggregate_function, MAX},
        {"basic_mode", no_argument, &basic_mode, 1},
        {"no_mem", no_argument, &no_mem, 1},
        {"no_normalization", no_argument, &no_normalization, 1},
        {"verbose", no_argument, &verbose, 1},
        {"cpu", required_argument, 0, 'p'},
        {"usr", required_argument, 0, 'r'},
        {"os", required_argument, 0, 's'},
        {"debug", no_argument, &debug, 1},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int option = 0;
    while ((option = getopt_long_only(argc, argv, "", long_opts, NULL)) != -1) {
        switch (option) {
            case 0:
                break;
            case 'c':
                code_length = mmap_file(optarg, &code);
                break;
            case 'i':
                code_init_length = mmap_file(optarg, &code_init);
                break;
            case 't':
                code_late_init_length = mmap_file(optarg, &code_late_init);
                break;
            case 'o':
                code_one_time_init_length = mmap_file(optarg, &code_one_time_init);
                break;
            case 'f': ;
                config_file_name = optarg;
                break;
            case 'n':
                n_measurements = atol(optarg);
                break;
            case 'u':
                unroll_count = atol(optarg);
                if (unroll_count <= 0) {
                    fprintf(stderr, "Error: unroll_count must be > 0\n");
                    return 1;
                }
                break;
            case 'l':
                loop_count = atol(optarg);
                break;
            case 'w':
                warm_up_count = atol(optarg);
                break;
            case 'a':
                initial_warm_up_count = atol(optarg);
                break;
            case 'm':
                alignment_offset = (size_t)atol(optarg);
                break;
            case 'p':
                cpu = atol(optarg);
                break;
            case 'r':
                usr = atoi(optarg);
                break;
            case 's':
                os = atoi(optarg);
                break;
            default:
                print_usage();
                return 1;
            }
    }

    /*************************************
     * Check CPUID and parse config file
     ************************************/
    if (check_cpuid()) {
        return 1;
    }

    if (config_file_name) {
        char* config_mmap;
        size_t len = mmap_file(config_file_name, &config_mmap);
        pfc_config_file_content = calloc(len+1, sizeof(char));
        memcpy(pfc_config_file_content, config_mmap, len);
        parse_counter_configs();
    }

    /*************************************
     * Pin thread to CPU
     ************************************/
    if (cpu == -1) {
        cpu = sched_getcpu();
    }

    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        fprintf(stderr, "Error: Could not pin thread to core %d\n", cpu);
        return 1;
    }

    /*************************************
     * Allocate memory
     ************************************/
    size_t runtime_code_length = get_required_runtime_code_length();
    posix_memalign((void**)&runtime_code, sysconf(_SC_PAGESIZE), runtime_code_length);
    if (!runtime_code) {
        fprintf(stderr, "Error: Failed to allocate memory for runtime_code\n");
        return 1;
    }
    if (mprotect(runtime_code, runtime_code_length, (PROT_READ | PROT_WRITE |PROT_EXEC))) {
        fprintf(stderr, "Error: mprotect failed\n");
        return 1;
    }

    size_t runtime_one_time_init_code_length = code_one_time_init_length + 10000;
    posix_memalign((void**)&runtime_one_time_init_code, sysconf(_SC_PAGESIZE), runtime_one_time_init_code_length);
    if (!runtime_one_time_init_code) {
        fprintf(stderr, "Error: Failed to allocate memory for runtime_one_time_init_code\n");
        return 1;
    }
    if (mprotect(runtime_one_time_init_code, runtime_one_time_init_code_length, (PROT_READ | PROT_WRITE |PROT_EXEC))) {
        fprintf(stderr, "Error: mprotect failed\n");
        return 1;
    }

    posix_memalign((void**)&runtime_r14, sysconf(_SC_PAGESIZE), RUNTIME_R_SIZE);
    posix_memalign((void**)&runtime_rbp, sysconf(_SC_PAGESIZE), RUNTIME_R_SIZE);
    posix_memalign((void**)&runtime_rdi, sysconf(_SC_PAGESIZE), RUNTIME_R_SIZE);
    posix_memalign((void**)&runtime_rsi, sysconf(_SC_PAGESIZE), RUNTIME_R_SIZE);
    posix_memalign((void**)&runtime_rsp, sysconf(_SC_PAGESIZE), RUNTIME_R_SIZE);
    if (!runtime_r14 || !runtime_rbp || !runtime_rdi || !runtime_rsi || !runtime_rsp) {
        fprintf(stderr, "Error: Could not allocate memory for runtime_r*\n");
        return 1;
    }
    runtime_r14 += RUNTIME_R_SIZE/2;
    runtime_rbp += RUNTIME_R_SIZE/2;
    runtime_rdi += RUNTIME_R_SIZE/2;
    runtime_rsi += RUNTIME_R_SIZE/2;
    runtime_rsp += RUNTIME_R_SIZE/2;

    for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
        measurement_results[i] = malloc(n_measurements*sizeof(int64_t));
        measurement_results_base[i] = malloc(n_measurements*sizeof(int64_t));
        if (!measurement_results[i] || !measurement_results_base[i]) {
            fprintf(stderr, "Error: Could not allocate memory for measurement_results\n");
            return 1;
        }
    }

    /*************************************
     * Fixed-function counters
     ************************************/
    long base_unroll_count = (basic_mode?0:unroll_count);
    long main_unroll_count = (basic_mode?unroll_count:2*unroll_count);
    long base_loop_count = (basic_mode?0:loop_count);
    long main_loop_count = loop_count;

    char buf[100];
    char* measurement_template;

    if (is_AMD_CPU) {
        if (no_mem) {
            measurement_template = (char*)&measurement_RDTSC_template_noMem;
        } else {
            measurement_template = (char*)&measurement_RDTSC_template;
        }
    } else {
        if (no_mem) {
            measurement_template = (char*)&measurement_FF_template_Intel_noMem;
        } else {
            measurement_template = (char*)&measurement_FF_template_Intel;
        }
    }

    create_and_run_one_time_init_code();
    run_warmup_experiment(measurement_template);

    if (is_AMD_CPU) {
        run_experiment(measurement_template, measurement_results_base, 1, base_unroll_count, base_loop_count);
        run_experiment(measurement_template, measurement_results, 1, main_unroll_count, main_loop_count);

        if (verbose) {
            printf("\nRDTSC results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
            print_all_measurement_results(measurement_results_base, 1);
            printf("RDTSC results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
            print_all_measurement_results(measurement_results, 1);
        }

        printf("%s", compute_result_str(buf, sizeof(buf), "RDTSC", 0));
    } else {
        configure_perf_ctrs_FF(usr, os);

        run_experiment(measurement_template, measurement_results_base, 4, base_unroll_count, base_loop_count);
        run_experiment(measurement_template, measurement_results, 4, main_unroll_count, main_loop_count);

        if (verbose) {
            printf("\nRDTSC and fixed-function counter results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
            print_all_measurement_results(measurement_results_base, 4);
            printf("RDTSC and fixed-function counter results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
            print_all_measurement_results(measurement_results, 4);
        }

        printf("%s", compute_result_str(buf, sizeof(buf), "RDTSC", 0));
        printf("%s", compute_result_str(buf, sizeof(buf), "Instructions retired", 1));
        printf("%s", compute_result_str(buf, sizeof(buf), "Core cycles", 2));
        printf("%s", compute_result_str(buf, sizeof(buf), "Reference cycles", 3));
    }

    /*************************************
     * Programmable counters
     ************************************/
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

    size_t next_pfc_config = 0;
    while (next_pfc_config < n_pfc_configs) {
        char* pfc_descriptions[MAX_PROGRAMMABLE_COUNTERS] = {0};
        next_pfc_config = configure_perf_ctrs_programmable(next_pfc_config, usr, os, pfc_descriptions);

        run_experiment(measurement_template, measurement_results_base, n_programmable_counters, base_unroll_count, base_loop_count);
        run_experiment(measurement_template, measurement_results, n_programmable_counters, main_unroll_count, main_loop_count);

        if (verbose) {
            printf("\nProgrammable counter results (unroll_count=%ld, loop_count=%ld):\n\n", base_unroll_count, base_loop_count);
            print_all_measurement_results(measurement_results_base, n_programmable_counters);
            printf("Programmable counter results (unroll_count=%ld, loop_count=%ld):\n\n", main_unroll_count, main_loop_count);
            print_all_measurement_results(measurement_results, n_programmable_counters);
        }

        for (size_t c=0; c < n_programmable_counters; c++) {
            if (pfc_descriptions[c]) printf("%s", compute_result_str(buf, sizeof(buf), pfc_descriptions[c], c));
        }
    }

    /*************************************
     * Cleanup
     ************************************/
    free(runtime_code);
    free(runtime_one_time_init_code);
    free(runtime_r14 - RUNTIME_R_SIZE/2);
    free(runtime_rbp - RUNTIME_R_SIZE/2);
    free(runtime_rdi - RUNTIME_R_SIZE/2);
    free(runtime_rsi - RUNTIME_R_SIZE/2);
    free(runtime_rsp - RUNTIME_R_SIZE/2);

    for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
        free(measurement_results[i]);
        free(measurement_results_base[i]);
    }

    if (pfc_config_file_content) {
        free(pfc_config_file_content);
    }

    return 0;
}

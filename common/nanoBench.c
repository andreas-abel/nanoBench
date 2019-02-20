#include "nanoBench.h"

long n_measurements = N_MEASUREMENTS_DEFAULT;
long unroll_count = UNROLL_COUNT_DEFAULT;
long loop_count = LOOP_COUNT_DEFAULT;
long warm_up_count = WARM_UP_COUNT_DEFAULT;
long initial_warm_up_count = INITIAL_WARM_UP_COUNT_DEFAULT;

int no_mem = NO_MEM_DEFAULT;
int basic_mode = BASIC_MODE_DEFAULT;
int aggregate_function = AGGREGATE_FUNCTION_DEFAULT;
int verbose = VERBOSE_DEFAULT;

char* code = NULL;
size_t code_length = 0;

char* code_init = NULL;
size_t code_init_length = 0;

struct pfc_config pfc_configs[1000] = {{0}};
size_t n_pfc_configs = 0;

char* pfc_config_file_content = NULL;

int is_Intel_CPU = 0;
int is_AMD_CPU = 0;

int n_programmable_counters;

char* runtime_code;
void* runtime_mem;
int64_t pfc_mem[MAX_PROGRAMMABLE_COUNTERS];
void* RSP_mem;

int64_t* measurement_results[MAX_PROGRAMMABLE_COUNTERS];
int64_t* measurement_results_base[MAX_PROGRAMMABLE_COUNTERS];

int cpu = -1;

void build_cpuid_string(char* buf, unsigned int r0, unsigned int r1, unsigned int r2, unsigned int r3) {
    memcpy(buf,    (char*)&r0, 4);
    memcpy(buf+4,  (char*)&r1, 4);
    memcpy(buf+8,  (char*)&r2, 4);
    memcpy(buf+12, (char*)&r3, 4);
}

int check_cpuid() {
    unsigned int eax, ebx, ecx, edx;
    __cpuid(0, eax, ebx, ecx, edx);
    
    char proc_vendor_string[17] = {0};
    build_cpuid_string(proc_vendor_string, ebx, edx, ecx, 0);
    print_user_verbose("Vendor ID: %s\n", proc_vendor_string);

    char proc_brand_string[48];
    __cpuid(0x80000002, eax, ebx, ecx, edx);
    build_cpuid_string(proc_brand_string, eax, ebx, ecx, edx);
    __cpuid(0x80000003, eax, ebx, ecx, edx);
    build_cpuid_string(proc_brand_string+16, eax, ebx, ecx, edx);
    __cpuid(0x80000004, eax, ebx, ecx, edx);
    build_cpuid_string(proc_brand_string+32, eax, ebx, ecx, edx);
    print_user_verbose("Brand: %s\n", proc_brand_string);
    
    __cpuid(0x01, eax, ebx, ecx, edx);
    unsigned int displ_family = ((eax >> 8) & 0xF);
    if (displ_family == 0x0F) {
        displ_family += ((eax >> 20) & 0xFF);
    }
    unsigned int displ_model = ((eax >> 4) & 0xF);
    if (displ_family == 0x06 || displ_family == 0x0F) {
        displ_model += ((eax >> 12) & 0xF0);
    }
    print_user_verbose("DisplayFamily_DisplayModel: %.2X_%.2XH\n", displ_family, displ_model);
    print_user_verbose("Stepping ID: %u\n", (eax & 0xF));

    if (strcmp(proc_vendor_string, "GenuineIntel") == 0) {
        is_Intel_CPU = 1;        
        n_programmable_counters = 4;
        
        __cpuid(0x0A, eax, ebx, ecx, edx);
        unsigned int perf_mon_ver = (eax & 0xFF);
        print_user_verbose("Performance monitoring version: %u\n", perf_mon_ver);
        if (perf_mon_ver < 2) {
            print_error("Error: performance monitoring version >= 2 required\n");
            return 1;
        }
        
        unsigned int n_available_counters = ((eax >> 8) & 0xFF);        
        print_user_verbose("Number of general-purpose performance counters: %u\n", n_available_counters);
        print_user_verbose("Bit widths of general-purpose performance counters: %u\n", ((eax >> 16) & 0xFF));

        if (n_available_counters < n_programmable_counters) {
            print_error("Error: only %u programmable counters available; nanoBench requires at least %u\n", n_available_counters, n_programmable_counters);
            return 1;
        }
    } else if (strcmp(proc_vendor_string, "AuthenticAMD") == 0) {
        is_AMD_CPU = 1;
        n_programmable_counters = 6;
    } else {
        print_error("Error: unsupported CPU found\n");
        return 1;
    }    
    
    return 0;
}

void parse_counter_configs() {
    n_pfc_configs = 0;
    
    char* line;
    char* next_line = pfc_config_file_content;
    while ((line = strsep(&next_line, "\n")) != NULL) {
        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }

        char* config_str = strsep(&line, " \t");

        if (line && strlen(line) > 0) {
            pfc_configs[n_pfc_configs].description = line;
        } else {
            pfc_configs[n_pfc_configs].description = config_str;
        }

        char buf[50];
        if (strlen(config_str) >= sizeof(buf)) {
            print_error("config string too long: %s\n", config_str);
            continue;
        }        
        strcpy(buf, config_str);
        
        char* tok = buf;
                      
        char* evt_num = strsep(&tok, ".");
        nb_strtoul(evt_num, 16, &(pfc_configs[n_pfc_configs].evt_num));
        
        if (!tok) {
            print_error("invalid configuration: %s\n", config_str);
            continue;
        }
                    
        char* umask = strsep(&tok, ".");
        nb_strtoul(umask, 16, &(pfc_configs[n_pfc_configs].umask));

        char* ce;
        while ((ce = strsep(&tok, ".")) != NULL) {
            if (!strcmp(ce, "AnyT")) {
                pfc_configs[n_pfc_configs].any = 1;
            } else if (!strcmp(ce, "EDG")) {
                pfc_configs[n_pfc_configs].edge = 1;
            } else if (!strcmp(ce, "INV")) {
                pfc_configs[n_pfc_configs].inv = 1;
            } else if (!strncmp(ce, "CTR=", 4)) {
                unsigned long counter;
                nb_strtoul(ce+4, 0, &counter);
                if (counter > n_programmable_counters) {
                    print_error("invalid counter: %s\n", ce);
                    continue;
                }
                size_t prev_n_pfc_configs = n_pfc_configs;
                while (n_pfc_configs % n_programmable_counters != counter) {
                    pfc_configs[n_pfc_configs].invalid = 1;
                    n_pfc_configs++;
                }
                if (prev_n_pfc_configs != n_pfc_configs) {
                    pfc_configs[n_pfc_configs] = pfc_configs[prev_n_pfc_configs];
                    pfc_configs[n_pfc_configs].invalid = 0;
                }
            } else if (!strncmp(ce, "CMSK=", 5)) {                
                nb_strtoul(ce+5, 0, &(pfc_configs[n_pfc_configs].cmask));
            } else if (!strncmp(ce, "MSR_3F6H=", 9)) {                
                nb_strtoul(ce+9, 0, &(pfc_configs[n_pfc_configs].msr_3f6h));
            } else if (!strncmp(ce, "MSR_PF=", 7)) {                
                nb_strtoul(ce+7, 0, &(pfc_configs[n_pfc_configs].msr_pf));
            } else if (!strncmp(ce, "MSR_RSP0=", 9)) {                
                nb_strtoul(ce+9, 0, &(pfc_configs[n_pfc_configs].msr_rsp0));
            } else if (!strncmp(ce, "MSR_RSP1=", 9)) {                
                nb_strtoul(ce+9, 0, &(pfc_configs[n_pfc_configs].msr_rsp1));
            }            
        }        
        n_pfc_configs++;
    }
}

#ifndef __KERNEL__
uint64_t read_value_from_cmd(char* cmd) {
    FILE* fp;
    if(!(fp = popen(cmd, "r"))){
        printf("Error reading from \"%s\"\n", cmd);
        return 0;
    }
    
    char buf[20];
    fgets(buf, sizeof(buf), fp);
    pclose(fp);
    
    uint64_t val;
    nb_strtoul(buf, 0, &val);
    return val;
}
#endif

uint64_t read_msr(unsigned int msr) {
    #ifdef __KERNEL__
        return native_read_msr(msr);
    #else    
        char cmd[50];
        snprintf(cmd, sizeof(cmd), "rdmsr -c -p%d %#x", cpu, msr);                
        return read_value_from_cmd(cmd);
    #endif
}

void write_msr(unsigned int msr, uint64_t value) {
    #ifdef __KERNEL__
        native_write_msr(msr, (uint32_t)value, (uint32_t)(value>>32));
    #else
        char cmd[50];
        snprintf(cmd, sizeof(cmd), "wrmsr -a -p%d %#x %#lx", cpu, msr, value);
        system(cmd);    
    #endif
}

void configure_perf_ctrs_FF(unsigned int usr, unsigned int os) {    
    if (is_Intel_CPU) {
        uint64_t global_ctrl = read_msr(MSR_IA32_PERF_GLOBAL_CTRL);        
        global_ctrl |= ((uint64_t)7 << 32) | 15;
        write_msr(MSR_IA32_PERF_GLOBAL_CTRL, global_ctrl);
                
        uint64_t fixed_ctrl = read_msr(MSR_IA32_FIXED_CTR_CTRL);
        // disable fixed counters
        fixed_ctrl &= ~((1 << 12) - 1);
        write_msr(MSR_IA32_FIXED_CTR_CTRL, fixed_ctrl);
        // clear
        for (int i=0; i<3; i++) {
            write_msr(MSR_IA32_FIXED_CTR0+i, 0);
        }
        //enable fixed counters
        fixed_ctrl |= (os << 8) | (os << 4) | os;
        fixed_ctrl |= (usr << 9) | (usr << 5) | (usr << 1);
        write_msr(MSR_IA32_FIXED_CTR_CTRL, fixed_ctrl);
    }
}

void configure_perf_ctrs_programmable(int start, int end, unsigned int usr, unsigned int os) {  
    if (is_Intel_CPU) {
        uint64_t global_ctrl = read_msr(MSR_IA32_PERF_GLOBAL_CTRL);        
        global_ctrl |= ((uint64_t)7 << 32) | 15;
        write_msr(MSR_IA32_PERF_GLOBAL_CTRL, global_ctrl);
        
        for (int i=0; i<n_programmable_counters; i++) {
            uint64_t perfevtselx = read_msr(MSR_IA32_PERFEVTSEL0+i);

            // disable counter i
            perfevtselx &= ~(((uint64_t)1 << 32) - 1);
            write_msr(MSR_IA32_PERFEVTSEL0+i, perfevtselx);

            // clear
            write_msr(MSR_IA32_PMC0+i, 0);

            if (start+i >= end) {
                continue;
            }

            // configure counter i
            struct pfc_config config = pfc_configs[start+i];
            if (config.invalid) {
                continue;
            }
            perfevtselx |= ((config.cmask & 0xFF) << 24);
            perfevtselx |= (config.inv << 23);
            perfevtselx |= (1ULL << 22);
            perfevtselx |= (config.any << 21);
            perfevtselx |= (config.edge << 18);
            perfevtselx |= (os << 17);
            perfevtselx |= (usr << 16);
            perfevtselx |= ((config.umask & 0xFF) << 8);
            perfevtselx |= (config.evt_num & 0xFF);
            write_msr(MSR_IA32_PERFEVTSEL0+i, perfevtselx);

            if (config.msr_3f6h) {
                write_msr(0x3f6, config.msr_3f6h);
            }

            if (config.msr_pf) {
                write_msr(MSR_PEBS_FRONTEND, config.msr_pf);
            }

            if (config.msr_rsp0) {
                write_msr(MSR_OFFCORE_RSP0, config.msr_rsp0);
            }
            if (config.msr_rsp1) {
                write_msr(MSR_OFFCORE_RSP1, config.msr_rsp1);
            }
        }
    } else {
        for (int i=0; i<n_programmable_counters; i++) {
            // clear
            write_msr(CORE_X86_MSR_PERF_CTR+(2*i), 0);
            
            if (start+i >= end) {
                write_msr(CORE_X86_MSR_PERF_CTL + (2*i), 0);
                continue;
            }
            
            struct pfc_config config = pfc_configs[start+i];
            
            uint64_t perf_ctl = 0;      
            perf_ctl |= ((config.evt_num) & 0xF00) << 24;
            perf_ctl |= (config.evt_num) & 0xFF;
            perf_ctl |= ((config.umask) & 0xFF) << 8;
            perf_ctl |= ((config.cmask) & 0x7F) << 24;
            perf_ctl |= (config.inv << 23);
            perf_ctl |= (1ULL << 22);
            perf_ctl |= (config.edge << 18);
            perf_ctl |= (os << 17);
            perf_ctl |= (usr << 16);            
            
            write_msr(CORE_X86_MSR_PERF_CTL + (2*i), perf_ctl);
        }
    }
}

void create_runtime_code(char* measurement_template, long local_unroll_count, long local_loop_count) {
    int templateI = 0;
    int rci = 0;
    
    while (!starts_with_magic_bytes(&measurement_template[templateI], MAGIC_BYTES_TEMPLATE_END)) {
        if (starts_with_magic_bytes(&measurement_template[templateI], MAGIC_BYTES_INIT)) {
            templateI += 8;
            memcpy(&runtime_code[rci], code_init, code_init_length);
            rci += code_init_length;
        } else if (starts_with_magic_bytes(&measurement_template[templateI], MAGIC_BYTES_CODE)) {
            templateI += 8;
            
            if (local_loop_count == 0) {
                for (long i=0; i<local_unroll_count; i++) {
                    memcpy(&runtime_code[rci], code, code_length);
                    rci += code_length;
                }
            } else {
                runtime_code[rci++] = '\x49'; runtime_code[rci++] = '\xC7'; runtime_code[rci++] = '\xC7';
                *(int32_t*)(&runtime_code[rci]) = (int32_t)local_loop_count; rci += 4; // mov R15, local_loop_count
                int rci_loop_start = rci;
                
                for (long i=0; i<local_unroll_count; i++) {
                    memcpy(&runtime_code[rci], code, code_length);
                    rci += code_length;
                }
                
                runtime_code[rci++] = '\x49'; runtime_code[rci++] = '\xFF'; runtime_code[rci++] = '\xCF'; //dec R15
                runtime_code[rci++] = '\x0F'; runtime_code[rci++] = '\x85';
                *(int32_t*)(&runtime_code[rci]) = (int32_t)(rci_loop_start-rci-4); rci += 4; // jnz loop_start
            }           
        } else if (starts_with_magic_bytes(&measurement_template[templateI], MAGIC_BYTES_PFC)) {
            *(void**)(&runtime_code[rci]) = pfc_mem;
            templateI += 8;
            rci += 8;
        } else if (starts_with_magic_bytes(&measurement_template[templateI], MAGIC_BYTES_RSP_ADDRESS)) {
            *(void**)(&runtime_code[rci]) = &RSP_mem;
            templateI += 8;
            rci += 8;
        } else if (starts_with_magic_bytes(&measurement_template[templateI], MAGIC_BYTES_RUNTIME_MEM)) {
            *(void**)(&runtime_code[rci]) = runtime_mem;
            templateI += 8;
            rci += 8;
        } else {            
            runtime_code[rci++] = measurement_template[templateI];
            templateI++;
        }
    }
    templateI += 8;
    do {
        runtime_code[rci++] = measurement_template[templateI++];
    } while (measurement_template[templateI-1] != '\xc3'); // 0xc3 = ret
}

void run_warmup_experiment(char* measurement_template) {
    if (!initial_warm_up_count) return;
    
    create_runtime_code(measurement_template, unroll_count, loop_count);
    
    for (int i=0; i<initial_warm_up_count; i++) {         
        ((void(*)(void))runtime_code)();
    }    
}

void run_experiment(char* measurement_template, int64_t* results[], int n_counters, long local_unroll_count, long local_loop_count) {
    create_runtime_code(measurement_template, local_unroll_count, local_loop_count);
    
    #ifdef __KERNEL__
        get_cpu();     
        unsigned long flags;
        raw_local_irq_save(flags);
    #endif
    
    for (long ri=-warm_up_count; ri<n_measurements; ri++) {
        ((void(*)(void))runtime_code)(); 

        // ignore "warm-up" runs (ri<0), but don't execute different branches
        long ri_ = (ri>=0)?ri:0;
        for (int c=0; c<n_counters; c++) {            
                results[c][ri_] = pfc_mem[c];
        }
    }
    
    #ifdef __KERNEL__
        raw_local_irq_restore(flags);
        put_cpu();
    #endif
}

char* compute_result_str(char* buf, size_t buf_len, char* desc, int counter) {
    int64_t agg = get_aggregate_value_100(measurement_results[counter], n_measurements);
    int64_t agg_base = get_aggregate_value_100(measurement_results_base[counter], n_measurements);
    
    int64_t n_rep = loop_count * unroll_count;
    if (loop_count == 0) {
        n_rep = unroll_count;
    }
    
    int64_t result = ((agg-agg_base) + n_rep/2)/n_rep;
    
    snprintf(buf, buf_len, "%s: %s%lld.%.2lld\n", desc, (result<0?"-":""), ll_abs(result/100), ll_abs(result)%100);
    return buf;
}

int64_t get_aggregate_value_100(int64_t* values, size_t length) {
    if (aggregate_function == MIN) {
        int64_t min = values[0];    
        for (int i=0; i<length; i++) {
            if (values[i] < min) {
                min = values[i];
            }
        }        
        return min * 100;
    } else {
        qsort(values, length, sizeof(int64_t), cmpInt64);

        if (aggregate_function == AVG_20_80) {
            // computes the average of the values between the 20 and 80 percentile
            int64_t sum = 0;
            int count = 0;
            for (int i=length/5; i<length-(length/5); i++, count++) {
                sum += (values[i] * 100);
            }            
            return sum/count;   
        } else {
            return values[length/2] * 100;
        }
    }
}

int cmpInt64(const void *a, const void *b) {
    return *(int64_t*)a - *(int64_t*)b;
}

long long ll_abs(long long val) {
    if (val < 0) {
        return -val;
    } else {
        return val;
    }
}

void print_all_measurement_results(int64_t* results[], int n_counters) {
    int run_padding = (n_measurements<=10?1:(n_measurements<=100?2:(n_measurements<=1000?3:4)));
    
    size_t size = 120;
    char buf[size];   
    
    sprintf(buf, "\t%*s      ", run_padding, "");
    for (int c=0; c<n_counters; c++) {        
        sprintf(buf + strlen(buf), "        Ctr%d", c);
    }
    print_verbose("%s\n", buf);

    for (int i=0; i<n_measurements; i++) {        
        sprintf(buf, "\trun %*d: ", run_padding, i);
        for (int c=0; c<n_counters; c++) {
            sprintf(buf + strlen(buf), "%12lld", (long long)results[c][i]);
        }
        print_verbose("%s\n", buf);
    }
    print_verbose("\n");
}

int starts_with_magic_bytes(char* c, int64_t magic_bytes) {
    return (*((int64_t*)c) == magic_bytes);
}

void measurement_template_Intel() { 
    SAVE_REGS_FLAGS();
    INITIALIZE_REGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "push rax                                \n"
        "lahf                                    \n"
        "push rax                                \n"
        "push rcx                                \n"
        "push rdx                                \n"
        "push r15                                \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov qword ptr [r15 + 0], 0              \n"
        "mov qword ptr [r15 + 8], 0              \n"
        "mov qword ptr [r15 + 16], 0             \n"
        "mov qword ptr [r15 + 24], 0             \n"
        "mov rcx, 0x00000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15 + 0], rdx                      \n"
        "mov rcx, 0x00000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15 + 8], rdx                      \n"
        "mov rcx, 0x00000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15 + 16], rdx                     \n"
        "mov rcx, 0x00000003                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15 + 24], rdx                     \n"
        "lfence                                  \n"
        "pop r15; lfence                         \n"
        "pop rdx; lfence                         \n"
        "pop rcx; lfence                         \n"
        "pop rax; lfence                         \n"
        "sahf; lfence                            \n"
        "pop rax;                                \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    ");    
    asm(".quad "STRINGIFY(MAGIC_BYTES_CODE));   
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "lfence                                  \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov rcx, 0x00000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15 + 0], rdx                      \n"
        "mov rcx, 0x00000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15 + 8], rdx                      \n"
        "mov rcx, 0x00000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15 + 16], rdx                     \n"
        "mov rcx, 0x00000003                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15 + 24], rdx                     \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    ");
    RESTORE_REGS_FLAGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_TEMPLATE_END));
}

void measurement_template_Intel_noMem() {   
    SAVE_REGS_FLAGS();
    INITIALIZE_REGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "mov r8, 0                               \n"
        "mov r9, 0                               \n"
        "mov r10, 0                              \n"
        "mov r11, 0                              \n"
        "mov rcx, 0x00000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r8, rdx                             \n"
        "mov rcx, 0x00000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r9, rdx                             \n"
        "mov rcx, 0x00000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r10, rdx                            \n"
        "mov rcx, 0x00000003                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r11, rdx                            \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    "); 
    asm(".quad "STRINGIFY(MAGIC_BYTES_CODE));   
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "lfence                                  \n"
        "mov rcx, 0x00000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r8, rdx                             \n"
        "mov rcx, 0x00000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r9, rdx                             \n"
        "mov rcx, 0x00000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r10, rdx                            \n"
        "mov rcx, 0x00000003                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r11, rdx                            \n"
        "mov rax, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov [rax + 0], r8                       \n"
        "mov [rax + 8], r9                       \n"
        "mov [rax + 16], r10                     \n"
        "mov [rax + 24], r11                     \n"
        ".att_syntax noprefix                    ");
    RESTORE_REGS_FLAGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_TEMPLATE_END));
}

void measurement_template_AMD() {   
    SAVE_REGS_FLAGS();
    INITIALIZE_REGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "push rax                                \n"
        "lahf                                    \n"
        "push rax                                \n"
        "push rcx                                \n"
        "push rdx                                \n"
        "push r15                                \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov qword ptr [r15 + 0], 0              \n"
        "mov qword ptr [r15 + 8], 0              \n"
        "mov qword ptr [r15 + 16], 0             \n"
        "mov qword ptr [r15 + 24], 0             \n"
        "mov qword ptr [r15 + 32], 0             \n"
        "mov qword ptr [r15 + 40], 0             \n"
        "mov rcx, 0x00000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15 + 0], rdx                      \n"
        "mov rcx, 0x00000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15 + 8], rdx                      \n"
        "mov rcx, 0x00000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15 + 16], rdx                     \n"
        "mov rcx, 0x00000003                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15 + 24], rdx                     \n"
        "mov rcx, 0x00000004                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15 + 32], rdx                     \n"
        "mov rcx, 0x00000005                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15 + 40], rdx                     \n"
        "lfence                                  \n"
        "pop r15; lfence                         \n"
        "pop rdx; lfence                         \n"
        "pop rcx; lfence                         \n"
        "pop rax; lfence                         \n"
        "sahf; lfence                            \n"
        "pop rax;                                \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    ");
    asm(".quad "STRINGIFY(MAGIC_BYTES_CODE));   
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "lfence                                  \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov rcx, 0x00000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15 + 0], rdx                      \n"
        "mov rcx, 0x00000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15 + 8], rdx                      \n"
        "mov rcx, 0x00000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15 + 16], rdx                     \n"
        "mov rcx, 0x00000003                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15 + 24], rdx                     \n"
        "mov rcx, 0x00000004                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15 + 32], rdx                     \n"
        "mov rcx, 0x00000005                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15 + 40], rdx                     \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    ");
    RESTORE_REGS_FLAGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_TEMPLATE_END));   
}

void measurement_template_AMD_noMem() { 
    SAVE_REGS_FLAGS();
    INITIALIZE_REGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "mov r8, 0                               \n"
        "mov r9, 0                               \n"
        "mov r10, 0                              \n"
        "mov r11, 0                              \n"
        "mov r12, 0                              \n"
        "mov r13, 0                              \n"
        "mov rcx, 0x00000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r8, rdx                             \n"
        "mov rcx, 0x00000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r9, rdx                             \n"
        "mov rcx, 0x00000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r10, rdx                            \n"
        "mov rcx, 0x00000003                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r11, rdx                            \n"
        "mov rcx, 0x00000004                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r12, rdx                            \n"
        "mov rcx, 0x00000005                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r13, rdx                            \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    "); 
    asm(".quad "STRINGIFY(MAGIC_BYTES_CODE));   
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "lfence                                  \n"
        "mov rcx, 0x00000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r8, rdx                             \n"
        "mov rcx, 0x00000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r9, rdx                             \n"
        "mov rcx, 0x00000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r10, rdx                            \n"
        "mov rcx, 0x00000003                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r11, rdx                            \n"
        "mov rcx, 0x00000004                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r12, rdx                            \n"
        "mov rcx, 0x00000005                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r13, rdx                            \n"
        "mov rax, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov [rax + 0], r8                       \n"
        "mov [rax + 8], r9                       \n"
        "mov [rax + 16], r10                     \n"
        "mov [rax + 24], r11                     \n"
        "mov [rax + 32], r12                     \n"
        "mov [rax + 40], r13                     \n"
        ".att_syntax noprefix                    ");
    RESTORE_REGS_FLAGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_TEMPLATE_END));
}

void measurement_FF_template_Intel() {  
    SAVE_REGS_FLAGS();
    INITIALIZE_REGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "push rax                                \n"
        "lahf                                    \n"
        "push rax                                \n"
        "push rcx                                \n"
        "push rdx                                \n"
        "push r15                                \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov qword ptr [r15], 0                  \n"
        "mov qword ptr [r15+8], 0                \n"
        "mov qword ptr [r15+16], 0               \n"
        "mov qword ptr [r15+24], 0               \n"
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15], rdx                          \n"
        "mov rcx, 0x40000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15+8], rdx                        \n"
        "mov rcx, 0x40000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15+24], rdx                       \n"
        "mov rcx, 0x40000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15+16], rdx;                      \n"
        "lfence                                  \n"
        "pop r15; lfence                         \n"
        "pop rdx; lfence                         \n"
        "pop rcx; lfence                         \n"
        "pop rax; lfence                         \n"
        "sahf; lfence                            \n"
        "pop rax;                                \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    ");
    asm(".quad "STRINGIFY(MAGIC_BYTES_CODE));   
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "lfence                                  \n"                
        "mov rcx, 0x40000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "add [r15+16], rdx                       \n"
        "mov rcx, 0x40000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15+8], rdx                        \n"
        "mov rcx, 0x40000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15+24], rdx                       \n"
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15], rdx                          \n"
        ".att_syntax noprefix                    ");
    RESTORE_REGS_FLAGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_TEMPLATE_END));
}

void measurement_FF_template_Intel_noMem() {    
    SAVE_REGS_FLAGS();
    INITIALIZE_REGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "mov r8, 0                               \n"
        "mov r9, 0                               \n"
        "mov r10, 0                              \n"
        "mov r11, 0                              \n"
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r8, rdx                             \n"
        "mov rcx, 0x40000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r9, rdx                             \n"
        "mov rcx, 0x40000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r10, rdx                            \n"
        "mov rcx, 0x40000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r11, rdx                            \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    ");
    asm(".quad "STRINGIFY(MAGIC_BYTES_CODE));   
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "lfence                                  \n"
        "mov rcx, 0x40000001                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r11, rdx                            \n"
        "mov rcx, 0x40000000                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r9, rdx                             \n"
        "mov rcx, 0x40000002                     \n"
        "lfence; rdpmc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r10, rdx                            \n"
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r8, rdx                             \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov [r15], r8                           \n"
        "mov [r15+8], r9                         \n"
        "mov [r15+16], r11                       \n"
        "mov [r15+24], r10                       \n"
        ".att_syntax noprefix                    ");
    RESTORE_REGS_FLAGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_TEMPLATE_END));   
}

void measurement_FF_template_AMD() {    
    SAVE_REGS_FLAGS();
    INITIALIZE_REGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "push rax                                \n"
        "lahf                                    \n"
        "push rax                                \n"
        "push rdx                                \n"
        "push r15                                \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov qword ptr [r15], 0                  \n"
        "mov qword ptr [r15+8], 0                \n"
        "mov qword ptr [r15+16], 0               \n"
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15], rdx                          \n"
        "mov rcx, 0x000000E7                     \n"
        "lfence; rdmsr; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15+8], rdx                        \n"
        "mov rcx, 0x000000E8                     \n"
        "lfence; rdmsr; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15+16], rdx                       \n"
        "lfence                                  \n"
        "pop r15; lfence                         \n"
        "pop rdx; lfence                         \n"
        "pop rax; lfence                         \n"
        "sahf; lfence                            \n"
        "pop rax;                                \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    ");
    asm(".quad "STRINGIFY(MAGIC_BYTES_CODE));   
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "lfence                                  \n"
        "mov rcx, 0x000000E8                     \n"
        "lfence; rdmsr; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "add [r15+16], rdx                       \n"
        "lfence                                  \n"
        "mov rcx, 0x000000E7                     \n"
        "lfence; rdmsr; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15+8], rdx                        \n"        
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add [r15], rdx                          \n"
        ".att_syntax noprefix                    ");
    RESTORE_REGS_FLAGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_TEMPLATE_END));
}

void measurement_FF_template_AMD_noMem() {
    SAVE_REGS_FLAGS();
    INITIALIZE_REGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "mov r8, 0                               \n"
        "mov r9, 0                               \n"
        "mov r10, 0                              \n"
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r8, rdx                             \n"
        "mov rcx, 0x000000E7                     \n"
        "lfence; rdmsr; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r9, rdx                             \n"
        "mov rcx, 0x000000E8                     \n"
        "lfence; rdmsr; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r10, rdx                            \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    ");
    asm(".quad "STRINGIFY(MAGIC_BYTES_CODE));   
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "lfence                                  \n"
        "mov rcx, 0x000000E8                     \n"
        "lfence; rdmsr; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r10, rdx                            \n"
        "mov rcx, 0x000000E7                     \n"
        "lfence; rdmsr; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r9, rdx                             \n"
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r8, rdx                             \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov [r15], r8                           \n"
        "mov [r15+8], r9                         \n"
        "mov [r15+16], r10                       \n"
        ".att_syntax noprefix                    ");
    RESTORE_REGS_FLAGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_TEMPLATE_END));
}

void measurement_RDTSC_template() { 
    SAVE_REGS_FLAGS();
    INITIALIZE_REGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "push rax                                \n"
        "lahf                                    \n"
        "push rax                                \n"
        "push rdx                                \n"
        "push r15                                \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov qword ptr [r15], 0                  \n"
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub [r15], rdx                          \n"
        "lfence                                  \n"
        "pop r15; lfence                         \n"
        "pop rdx; lfence                         \n"
        "pop rax; lfence                         \n"
        "sahf; lfence                            \n"
        "pop rax;                                \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    ");
    asm(".quad "STRINGIFY(MAGIC_BYTES_CODE));   
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "lfence                                  \n"
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "add [r15], rdx                          \n"
        ".att_syntax noprefix                    ");
    RESTORE_REGS_FLAGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_TEMPLATE_END));
}

void measurement_RDTSC_template_noMem() {
    SAVE_REGS_FLAGS();
    INITIALIZE_REGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "mov r8, 0                               \n"
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "sub r8, rdx                             \n"
        "lfence                                  \n"
        ".att_syntax noprefix                    ");
    asm(".quad "STRINGIFY(MAGIC_BYTES_CODE));   
    asm volatile(
        ".intel_syntax noprefix                  \n"
        "lfence                                  \n"
        "lfence; rdtsc; lfence                   \n"
        "shl rdx, 32; or rdx, rax                \n"
        "add r8, rdx                             \n"
        "mov r15, "STRINGIFY(MAGIC_BYTES_PFC)"   \n"
        "mov [r15], r8                           \n"
        ".att_syntax noprefix                    ");
    RESTORE_REGS_FLAGS();
    asm(".quad "STRINGIFY(MAGIC_BYTES_TEMPLATE_END));
}

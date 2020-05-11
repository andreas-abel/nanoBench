#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Error: nanoBench requires root privileges"
    echo "Try \"sudo ./nb_km-asm.sh ...\""
    exit 1
fi

if [ ! -e /sys/nb ]; then
    echo "Error: nanoBench kernel module not loaded"
    echo "Load with \"sudo insmod nb.ko\""
    exit 1
fi

cat /sys/nb/reset

taskset=""

while [ "$1" ]; do
    if [[ "$1" == -asm_i* ]]; then
        echo ".intel_syntax noprefix" > asm-init.s
        echo "$2" >> asm-init.s
        as asm-init.s -o asm-init.o
        objcopy asm-init.o -O binary asm-init.o
        echo -n "asm-init.o" > /sys/nb/init
        rm -f asm-init.s asm-init.o
        shift 2
    elif [[ "$1" == -asm_o* ]]; then
        echo ".intel_syntax noprefix" > asm-one-time-init.s
        echo "$2" >> asm-one-time-init.s
        as asm-one-time-init.s -o asm-one-time-init.o
        objcopy asm-one-time-init.o -O binary asm-one-time-init.o
        echo -n "asm-one-time-init.o" > /sys/nb/one_time_init
        rm -f asm-one-time-init.s asm-one-time-init.o
        shift 2
    elif [[ "$1" == -as* ]]; then
        echo ".intel_syntax noprefix" > asm-code.s
        echo "$2" >> asm-code.s
        as asm-code.s -o asm-code.o
        objcopy asm-code.o -O binary asm-code.o
        echo -n "asm-code.o" > /sys/nb/code
        rm -f asm-code.s asm-code.o
        shift 2
    elif [[ "$1" == -code_i* ]]; then
        echo -n "$2" > /sys/nb/init
        shift 2
    elif [[ "$1" == -code_o* ]]; then
        echo -n "$2" > /sys/nb/one_time_init
        shift 2
    elif [[ "$1" == -cod* ]]; then
        echo -n "$2" > /sys/nb/code
        shift 2
    elif [[ "$1" == -cpu ]]; then
        taskset="taskset -c $2"
        shift 2    
    elif [[ "$1" == -con* ]]; then
        echo -n "$2" > /sys/nb/config
        shift 2
    elif [[ "$1" == -msr* ]]; then
        echo -n "$2" > /sys/nb/msr_config
        shift 2
    elif [[ "$1" == -u* ]]; then
        echo "$2" > /sys/nb/unroll_count
        shift 2
    elif [[ "$1" == -l* ]]; then
        echo "$2" > /sys/nb/loop_count
        shift 2
    elif [[ "$1" == -no_mem ]]; then
        echo "1" > /sys/nb/no_mem
        shift
    elif [[ "$1" == -n* ]]; then
        echo "$2" > /sys/nb/n_measurements
        shift 2
    elif [[ "$1" == -b* ]]; then
        echo "1" > /sys/nb/basic_mode
        shift
    elif [[ "$1" == -v* ]]; then
        echo "1" > /sys/nb/verbose
        shift
    elif [[ "$1" == -w* ]]; then
        echo "$2" > /sys/nb/warm_up
        shift 2
    elif [[ "$1" == -initial* ]]; then
        echo "$2" > /sys/nb/initial_warm_up
        shift 2
    elif [[ "$1" == -al* ]]; then
        echo "$2" > /sys/nb/alignment_offset
        shift 2
    elif [[ "$1" == -min* ]]; then
        echo "min" > /sys/nb/agg
        shift
    elif [[ "$1" == -med* ]]; then
        echo "med" > /sys/nb/agg
        shift
    elif [[ "$1" == -avg* ]]; then
        echo "avg" > /sys/nb/agg
        shift
    elif [[ "$1" == -h* ]]; then
        echo "kernel-nanoBench.sh usage:"
        echo
	echo "  -asm <code>:                Assembler code string (in Intel syntax) to be benchmarked."
	echo "  -asm_init <code>:           Assembler code string (in Intel syntax) to be executed once in the beginning"
        echo "  -code <filename>:           Binary file containing the code to be benchmarked."
        echo "  -code_init <filename>:      Binary file containing code to be executed once in the beginning"
        echo "  -config <filename>:         File with performance counter event specifications."
        echo "  -n_measurements <n>:        Number of times the measurements are repeated."
        echo "  -unroll_count <n>:          Number of copies of the benchmark code inside the inner loop."
        echo "  -loop_count <n>:            Number of iterations of the inner loop."
        echo "  -warm_up_count <n>:         Number of runs before the first measurement gets recorded."
        echo "  -initial_warm_up_count <n>: Number of runs before any measurement is performed."
        echo "  -alignment_offset <n>:      Alignment offset."
        echo "  -avg:                       Selects the arithmetic mean as the aggregate function."
        echo "  -median:                    Selects the median as the aggregate function."
        echo "  -min:                       Selects the minimum as the aggregate function."
        echo "  -basic_mode:                Enables basic mode."
        echo "  -no_mem:                    The code for reading the perf. ctrs. does not make memory accesses."
        echo "  -cpu <n>:                   Pins the measurement thread to CPU n."
        echo "  -verbose:                   Outputs the results of all performance counter readings."        
        exit 0
    else
        echo "Invalid option: $1"
        exit 1
    fi
done

$taskset cat /proc/nanoBench

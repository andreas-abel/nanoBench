#!/usr/bin/env bash

source utils.sh

if [ "$EUID" -ne 0 ]; then
    echo "Error: nanoBench requires root privileges" >&2
    echo "Try \"sudo ./nanoBench-asm.sh ...\"" >&2
    exit 1
fi

if ! command -v rdmsr &>/dev/null; then
    echo "Error: nanoBench requires msr-tools" >&2
    echo "Install with \"sudo apt install msr-tools\"" >&2
    exit 1
fi

if [ $(cat /sys/devices/system/cpu/smt/active) -ne 0 ]; then
    echo "Note: Hyper-threading is enabled; it can be disabled with \"sudo ./disable-HT.sh\"" >&2
fi

debug=""
filter_output="cat"

args=''
while [ "$1" ]; do
    if [[ "$1" == -asm_i* ]]; then
        assemble "$2" asm-init.bin
        args="$args -code_init asm-init.bin"
        shift 2
    elif [[ "$1" == -asm_l* ]]; then
        assemble "$2" asm-late-init.bin
        args="$args -code_late_init asm-late-init.bin"
        shift 2
    elif [[ "$1" == -asm_o* ]]; then
        assemble "$2" asm-one-time-init.bin
        args="$args -code_one_time_init asm-one-time-init.bin"
        shift 2
    elif [[ "$1" == -as* ]]; then
        assemble "$2" asm-code.bin
        args="$args -code asm-code.bin"
        shift 2
    elif [[ "$1" == -de* ]]; then
        debug="gdb -ex=run --args"
        args="$args $1"
        shift
    elif [[ "$1" == -re* ]]; then
        filter_output="grep -v 0.00"
        shift
    else
        args="$args $1"
        shift
    fi
done
set "$args"

if [ -d "/sys/bus/event_source/devices/cpu" ]; then
    prev_rdpmc=$(cat /sys/bus/event_source/devices/cpu/rdpmc)
    echo 2 > /sys/bus/event_source/devices/cpu/rdpmc || exit 1
else
    prev_rdpmc_atom=$(cat /sys/bus/event_source/devices/cpu_atom/rdpmc)
    prev_rdpmc_core=$(cat /sys/bus/event_source/devices/cpu_core/rdpmc)
    echo 2 > /sys/bus/event_source/devices/cpu_atom/rdpmc || exit 1
    echo 2 > /sys/bus/event_source/devices/cpu_core/rdpmc || exit 1
fi

modprobe --first-time msr &>/dev/null
msr_prev_loaded=$?

# (Temporarily) disable watchdogs, see https://github.com/obilaniu/libpfc
! modprobe --first-time -r iTCO_wdt &>/dev/null
iTCO_wdt_prev_loaded=$?

! modprobe --first-time -r iTCO_vendor_support &>/dev/null
iTCO_vendor_support_prev_loaded=$?

prev_nmi_watchdog=$(cat /proc/sys/kernel/nmi_watchdog)
[ $prev_nmi_watchdog != 0 ] && echo 0 > /proc/sys/kernel/nmi_watchdog

$debug user/nanoBench $@ | $filter_output
return_value=${PIPESTATUS[0]}

rm -f asm-*.bin

[ $prev_nmi_watchdog != 0 ] && echo $prev_nmi_watchdog > /proc/sys/kernel/nmi_watchdog

if [ -d "/sys/bus/event_source/devices/cpu" ]; then
    echo $prev_rdpmc > /sys/bus/event_source/devices/cpu/rdpmc
else
    echo $prev_rdpmc_atom > /sys/bus/event_source/devices/cpu_atom/rdpmc
    echo $prev_rdpmc_core > /sys/bus/event_source/devices/cpu_core/rdpmc
fi

if [[ $msr_prev_loaded == 0 ]]; then
    modprobe -r msr
fi

if [[ $iTCO_wdt_prev_loaded != 0 ]]; then
    modprobe iTCO_wdt &>/dev/null
fi

if [[ $iTCO_vendor_support_prev_loaded != 0 ]]; then
    modprobe iTCO_vendor_support &>/dev/null
fi

exit $return_value

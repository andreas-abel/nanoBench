#!/usr/bin/env bash

source utils.sh

if [ "$EUID" -ne 0 ]; then
    echo "Error: nanoBench requires root privileges" 1>&2
    echo "Try \"sudo ./nanoBench-asm.sh ...\"" 1>&2
    exit 1
fi

if ! command -v rdmsr &>/dev/null; then
    echo "Error: nanoBench requires msr-tools"
    echo "Install with \"sudo apt install msr-tools\""
    exit 1
fi

debug=false
for p in "$@"; do
    if [[ "$p" == -de* ]]; then
        debug=true
    fi
done

args=''
while [ "$2" ]; do
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
    else
        args="$args $1"
        shift
    fi
done
args="$args $1"
set "$args"

prev_rdpmc=$(cat /sys/bus/event_source/devices/cpu/rdpmc)
echo 2 > /sys/bus/event_source/devices/cpu/rdpmc || exit

modprobe --first-time msr &>/dev/null
msr_prev_loaded=$?

# (Temporarily) disable watchdogs, see https://github.com/obilaniu/libpfc
! modprobe --first-time -r iTCO_wdt &>/dev/null
iTCO_wdt_prev_loaded=$?

! modprobe --first-time -r iTCO_vendor_support &>/dev/null
iTCO_vendor_support_prev_loaded=$?

prev_nmi_watchdog=$(cat /proc/sys/kernel/nmi_watchdog)
echo 0 > /proc/sys/kernel/nmi_watchdog

if [ "$debug" = true ]; then
    gdb -ex=run --args user/nanoBench $@
    return_value=$?
else
    user/nanoBench $@
    return_value=$?
fi

rm -f asm-*.bin

echo $prev_rdpmc > /sys/bus/event_source/devices/cpu/rdpmc
echo $prev_nmi_watchdog > /proc/sys/kernel/nmi_watchdog

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

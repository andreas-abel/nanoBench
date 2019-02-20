#!/bin/bash

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

args=''
while [ "$2" ]; do
    if [ "$1" == '-asm' ]; then
        echo ".intel_syntax noprefix" > asm-code.s
        echo "$2" >> asm-code.s
        as asm-code.s -o asm-code.o || exit
        objcopy asm-code.o -O binary asm-code.bin
        args="$args -code asm-code.bin"
        shift 2
    elif [ "$1" == '-asm_init' ]; then
        echo ".intel_syntax noprefix" > asm-init.s
        echo "$2" >> asm-init.s
        as asm-init.s -o asm-init.o || exit
        objcopy asm-init.o -O binary asm-init.bin
        args="$args -code_init asm-init.bin"
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

user/nanoBench $@

rm -f asm-code.*
rm -f asm-init.*

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

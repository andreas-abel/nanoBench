#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2021 Andreas Abel
#
# This file was modified from https://github.com/flababah/cpuid.py
#
# Original license and copyright notice:
#
#    The MIT License (MIT)
#
#    Copyright (c) 2014 Anders Høst
#
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import collections
import ctypes
import os
import platform
import struct
import sys

from ctypes import c_uint32, c_int, c_long, c_ulong, c_size_t, c_void_p, POINTER, CFUNCTYPE

import logging
log = logging.getLogger(__name__)

# Posix x86_64:
# Three first call registers : RDI, RSI, RDX
# Volatile registers         : RAX, RCX, RDX, RSI, RDI, R8-11

# Windows x86_64:
# Three first call registers : RCX, RDX, R8
# Volatile registers         : RAX, RCX, RDX, R8-11

# cdecl 32 bit:
# Three first call registers : Stack (%esp)
# Volatile registers         : EAX, ECX, EDX

_POSIX_64_OPC = [
        0x53,                    # push   %rbx
        0x89, 0xf0,              # mov    %esi,%eax
        0x89, 0xd1,              # mov    %edx,%ecx
        0x0f, 0xa2,              # cpuid
        0x89, 0x07,              # mov    %eax,(%rdi)
        0x89, 0x5f, 0x04,        # mov    %ebx,0x4(%rdi)
        0x89, 0x4f, 0x08,        # mov    %ecx,0x8(%rdi)
        0x89, 0x57, 0x0c,        # mov    %edx,0xc(%rdi)
        0x5b,                    # pop    %rbx
        0xc3                     # retq
]

_WINDOWS_64_OPC = [
        0x53,                    # push   %rbx
        0x89, 0xd0,              # mov    %edx,%eax
        0x49, 0x89, 0xc9,        # mov    %rcx,%r9
        0x44, 0x89, 0xc1,        # mov    %r8d,%ecx
        0x0f, 0xa2,              # cpuid
        0x41, 0x89, 0x01,        # mov    %eax,(%r9)
        0x41, 0x89, 0x59, 0x04,  # mov    %ebx,0x4(%r9)
        0x41, 0x89, 0x49, 0x08,  # mov    %ecx,0x8(%r9)
        0x41, 0x89, 0x51, 0x0c,  # mov    %edx,0xc(%r9)
        0x5b,                    # pop    %rbx
        0xc3                     # retq
]

_CDECL_32_OPC = [
        0x53,                    # push   %ebx
        0x57,                    # push   %edi
        0x8b, 0x7c, 0x24, 0x0c,  # mov    0xc(%esp),%edi
        0x8b, 0x44, 0x24, 0x10,  # mov    0x10(%esp),%eax
        0x8b, 0x4c, 0x24, 0x14,  # mov    0x14(%esp),%ecx
        0x0f, 0xa2,              # cpuid
        0x89, 0x07,              # mov    %eax,(%edi)
        0x89, 0x5f, 0x04,        # mov    %ebx,0x4(%edi)
        0x89, 0x4f, 0x08,        # mov    %ecx,0x8(%edi)
        0x89, 0x57, 0x0c,        # mov    %edx,0xc(%edi)
        0x5f,                    # pop    %edi
        0x5b,                    # pop    %ebx
        0xc3                     # ret
]

is_windows = os.name == "nt"
is_64bit   = ctypes.sizeof(ctypes.c_voidp) == 8

class CPUID_struct(ctypes.Structure):
    _fields_ = [(r, c_uint32) for r in ("eax", "ebx", "ecx", "edx")]

class CPUID(object):
    def __init__(self):
        if platform.machine() not in ("AMD64", "x86_64", "x86", "i686"):
            raise SystemError("Only available for x86")

        if is_windows:
            if is_64bit:
                # VirtualAlloc seems to fail under some weird
                # circumstances when ctypes.windll.kernel32 is
                # used under 64 bit Python. CDLL fixes this.
                self.win = ctypes.CDLL("kernel32.dll")
                opc = _WINDOWS_64_OPC
            else:
                # Here ctypes.windll.kernel32 is needed to get the
                # right DLL. Otherwise it will fail when running
                # 32 bit Python on 64 bit Windows.
                self.win = ctypes.windll.kernel32
                opc = _CDECL_32_OPC
        else:
            opc = _POSIX_64_OPC if is_64bit else _CDECL_32_OPC

        size = len(opc)
        code = (ctypes.c_ubyte * size)(*opc)

        if is_windows:
            self.win.VirtualAlloc.restype = c_void_p
            self.win.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
            self.addr = self.win.VirtualAlloc(None, size, 0x1000, 0x40)
            if not self.addr:
                raise MemoryError("Could not allocate RWX memory")
        else:
            self.libc = ctypes.cdll.LoadLibrary(None)
            self.libc.valloc.restype = ctypes.c_void_p
            self.libc.valloc.argtypes = [ctypes.c_size_t]
            self.addr = self.libc.valloc(size)
            if not self.addr:
                raise MemoryError("Could not allocate memory")

            self.libc.mprotect.restype = c_int
            self.libc.mprotect.argtypes = [c_void_p, c_size_t, c_int]
            ret = self.libc.mprotect(self.addr, size, 1 | 2 | 4)
            if ret != 0:
                raise OSError("Failed to set RWX")


        ctypes.memmove(self.addr, code, size)

        func_type = CFUNCTYPE(None, POINTER(CPUID_struct), c_uint32, c_uint32)
        self.func_ptr = func_type(self.addr)

    def __call__(self, eax, ecx=0):
        struct = CPUID_struct()
        self.func_ptr(struct, eax, ecx)
        return struct.eax, struct.ebx, struct.ecx, struct.edx

    def __del__(self):
        if is_windows:
            self.win.VirtualFree.restype = c_long
            self.win.VirtualFree.argtypes = [c_void_p, c_size_t, c_ulong]
            self.win.VirtualFree(self.addr, 0, 0x8000)
        elif self.libc:
            # Seems to throw exception when the program ends and
            # libc is cleaned up before the object?
            self.libc.free.restype = None
            self.libc.free.argtypes = [c_void_p]
            self.libc.free(self.addr)

def cpu_vendor(cpu):
    _, b, c, d = cpu(0)
    return str(struct.pack("III", b, d, c).decode("ascii"))

def cpu_name(cpu):
    return " ".join(str("".join((struct.pack("IIII", *cpu(0x80000000 + i)).decode("ascii")
            for i in range(2, 5))).replace('\x00', '')).split())

VersionInfo = collections.namedtuple('VersionInfo', 'displ_family displ_model stepping core_type')

def version_info(cpu):
   a, _, _, _ = cpu(0x01)

   family_ID = (a >> 8) & 0xF

   displ_family = family_ID
   if (family_ID == 0x0F):
      displ_family += (a >> 20) & 0xFF

   displ_model = (a >> 4) & 0xF
   if (family_ID == 0x06 or family_ID == 0x0F):
      displ_model += (a >> 12) & 0xF0

   stepping = a & 0xF

   core_type = 0
   if 0x1A <= cpu(0x0)[0]:
      core_type = (cpu(0x1A)[0] >> 24)

   return VersionInfo(int(displ_family), int(displ_model), int(stepping), int(core_type))

def micro_arch(cpu):
   vi = version_info(cpu)

   if (vi.displ_family, vi.displ_model) in [(0x06, 0x0F)]:
      return 'Core'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x17)]:
      return 'EnhancedCore'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x1A), (0x06, 0x1E), (0x06, 0x1F), (0x06, 0x2E)]:
      return 'NHM'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x25), (0x06, 0x2C), (0x06, 0x2F)]:
      return 'WSM'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x1C), (0x06, 0x26), (0x06, 0x27), (0x06, 0x35), (0x06, 0x36)]:
      return 'BNL'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x2A)]:
      return 'SNB'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x2D)]:
      return 'JKT'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x3A)]:
      return 'IVB'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x3E)]:
      return 'IVT'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x3C), (0x06, 0x45), (0x06, 0x46)]:
      return 'HSW'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x3F)]:
      return 'HSX'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x3D), (0x06, 0x47), (0x06, 0x56), (0x06, 0x4F)]:
      return 'BDW'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x37), (0x06, 0x4C), (0x06, 0x4D)]:
      return 'SLM'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x5C), (0x06, 0x5F)]:
      return 'GLM'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x57)]:
      return 'KNL'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x4E), (0x06, 0x5E)]:
      return 'SKL'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x55)]:
      if vi.stepping <= 0x4:
         return 'SKX'
      else:
         return 'CLX'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x8E), (0x06, 0x9E)]:
      # ToDo: not sure if this is correct
      if vi.stepping <= 0x9:
         return 'KBL'
      else:
         return 'CFL'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x66)]:
      return 'CNL'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x7A)]:
      return 'GLP'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x7D), (0x06, 0x7E)]:
      return 'ICL'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x85)]:
      return 'KNM'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x86)]:
      return 'SNR'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x8C), (0x06, 0x8D)]:
      return 'TGL'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0xA7)]:
      return 'RKL'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x6A), (0x06, 0x6C)]:
      return 'ICX'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x96)]:
      return 'EHL'
   if (vi.displ_family, vi.displ_model) in [(0x06, 0x97), (0x06, 0x9A)]:
      return 'ADL-' + ('P' if (vi.core_type == 0x40) else 'E')
   if (vi.displ_family, vi.displ_model) in [(0x17, 0x01), (0x17, 0x11)]:
      return 'ZEN'
   if (vi.displ_family, vi.displ_model) in [(0x17, 0x08), (0x17, 0x18)]:
      return 'ZEN+'
   if (vi.displ_family, vi.displ_model) in [(0x17, 0x71)]:
      return 'ZEN2'
   if (vi.displ_family, vi.displ_model) in [(0x19, 0x21)]:
      return 'ZEN3'

   return 'unknown'

# See Table 3-12 (Encoding of CPUID Leaf 2 Descriptors) in Intel's Instruction Set Reference
leaf2_descriptors = {
   0x01: ('TLB', 'Instruction TLB: 4 KByte pages, 4-way set associative, 32 entries'),
   0x02: ('TLB', 'Instruction TLB: 4 MByte pages, fully associative, 2 entries'),
   0x03: ('TLB', 'Data TLB: 4 KByte pages, 4-way set associative, 64 entries'),
   0x04: ('TLB', 'Data TLB: 4 MByte pages, 4-way set associative, 8 entries'),
   0x05: ('TLB', 'Data TLB1: 4 MByte pages, 4-way set associative, 32 entries'),
   0x06: ('Cache', '1st-level instruction cache: 8 KBytes, 4-way set associative, 32 byte line size'),
   0x08: ('Cache', '1st-level instruction cache: 16 KBytes, 4-way set associative, 32 byte line size'),
   0x09: ('Cache', '1st-level instruction cache: 32KBytes, 4-way set associative, 64 byte line size'),
   0x0A: ('Cache', '1st-level data cache: 8 KBytes, 2-way set associative, 32 byte line size'),
   0x0B: ('TLB', 'Instruction TLB: 4 MByte pages, 4-way set associative, 4 entries'),
   0x0C: ('Cache', '1st-level data cache: 16 KBytes, 4-way set associative, 32 byte line size'),
   0x0D: ('Cache', '1st-level data cache: 16 KBytes, 4-way set associative, 64 byte line size'),
   0x0E: ('Cache', '1st-level data cache: 24 KBytes, 6-way set associative, 64 byte line size'),
   0x1D: ('Cache', '2nd-level cache: 128 KBytes, 2-way set associative, 64 byte line size'),
   0x21: ('Cache', '2nd-level cache: 256 KBytes, 8-way set associative, 64 byte line size'),
   0x22: ('Cache', '3rd-level cache: 512 KBytes, 4-way set associative, 64 byte line size, 2 lines per sector'),
   0x23: ('Cache', '3rd-level cache: 1 MBytes, 8-way set associative, 64 byte line size, 2 lines per sector'),
   0x24: ('Cache', '2nd-level cache: 1 MBytes, 16-way set associative, 64 byte line size'),
   0x25: ('Cache', '3rd-level cache: 2 MBytes, 8-way set associative, 64 byte line size, 2 lines per sector'),
   0x29: ('Cache', '3rd-level cache: 4 MBytes, 8-way set associative, 64 byte line size, 2 lines per sector'),
   0x2C: ('Cache', '1st-level data cache: 32 KBytes, 8-way set associative, 64 byte line size'),
   0x30: ('Cache', '1st-level instruction cache: 32 KBytes, 8-way set associative, 64 byte line size'),
   0x40: ('Cache', 'No 2nd-level cache or, if processor contains a valid 2nd-level cache, no 3rd-level cache'),
   0x41: ('Cache', '2nd-level cache: 128 KBytes, 4-way set associative, 32 byte line size'),
   0x42: ('Cache', '2nd-level cache: 256 KBytes, 4-way set associative, 32 byte line size'),
   0x43: ('Cache', '2nd-level cache: 512 KBytes, 4-way set associative, 32 byte line size'),
   0x44: ('Cache', '2nd-level cache: 1 MByte, 4-way set associative, 32 byte line size'),
   0x45: ('Cache', '2nd-level cache: 2 MByte, 4-way set associative, 32 byte line size'),
   0x46: ('Cache', '3rd-level cache: 4 MByte, 4-way set associative, 64 byte line size'),
   0x47: ('Cache', '3rd-level cache: 8 MByte, 8-way set associative, 64 byte line size'),
   0x48: ('Cache', '2nd-level cache: 3MByte, 12-way set associative, 64 byte line size'),
   0x49: ('Cache', '3rd-level cache: 4MB, 16-way set associative, 64-byte line size (Intel Xeon processor MP, Family 0FH, Model 06H); 2nd-level cache: 4 MByte, 16-way set associative, 64 byte line size'),
   0x4A: ('Cache', '3rd-level cache: 6MByte, 12-way set associative, 64 byte line size'),
   0x4B: ('Cache', '3rd-level cache: 8MByte, 16-way set associative, 64 byte line size'),
   0x4C: ('Cache', '3rd-level cache: 12MByte, 12-way set associative, 64 byte line size'),
   0x4D: ('Cache', '3rd-level cache: 16MByte, 16-way set associative, 64 byte line size'),
   0x4E: ('Cache', '2nd-level cache: 6MByte, 24-way set associative, 64 byte line size'),
   0x4F: ('TLB', 'Instruction TLB: 4 KByte pages, 32 entries'),
   0x50: ('TLB', 'Instruction TLB: 4 KByte and 2-MByte or 4-MByte pages, 64 entries'),
   0x51: ('TLB', 'Instruction TLB: 4 KByte and 2-MByte or 4-MByte pages, 128 entries'),
   0x52: ('TLB', 'Instruction TLB: 4 KByte and 2-MByte or 4-MByte pages, 256 entries'),
   0x55: ('TLB', 'Instruction TLB: 2-MByte or 4-MByte pages, fully associative, 7 entries'),
   0x56: ('TLB', 'Data TLB0: 4 MByte pages, 4-way set associative, 16 entries'),
   0x57: ('TLB', 'Data TLB0: 4 KByte pages, 4-way associative, 16 entries'),
   0x59: ('TLB', 'Data TLB0: 4 KByte pages, fully associative, 16 entries'),
   0x5A: ('TLB', 'Data TLB0: 2 MByte or 4 MByte pages, 4-way set associative, 32 entries'),
   0x5B: ('TLB', 'Data TLB: 4 KByte and 4 MByte pages, 64 entries'),
   0x5C: ('TLB', 'Data TLB: 4 KByte and 4 MByte pages,128 entries'),
   0x5D: ('TLB', 'Data TLB: 4 KByte and 4 MByte pages,256 entries'),
   0x60: ('Cache', '1st-level data cache: 16 KByte, 8-way set associative, 64 byte line size'),
   0x61: ('TLB', 'Instruction TLB: 4 KByte pages, fully associative, 48 entries'),
   0x63: ('TLB', 'Data TLB: 2 MByte or 4 MByte pages, 4-way set associative, 32 entries and a separate array with 1 GByte pages, 4-way set associative, 4 entries'),
   0x64: ('TLB', 'Data TLB: 4 KByte pages, 4-way set associative, 512 entries'),
   0x66: ('Cache', '1st-level data cache: 8 KByte, 4-way set associative, 64 byte line size'),
   0x67: ('Cache', '1st-level data cache: 16 KByte, 4-way set associative, 64 byte line size'),
   0x68: ('Cache', '1st-level data cache: 32 KByte, 4-way set associative, 64 byte line size'),
   0x6A: ('Cache', 'uTLB: 4 KByte pages, 8-way set associative, 64 entries'),
   0x6B: ('Cache', 'DTLB: 4 KByte pages, 8-way set associative, 256 entries'),
   0x6C: ('Cache', 'DTLB: 2M/4M pages, 8-way set associative, 128 entries'),
   0x6D: ('Cache', 'DTLB: 1 GByte pages, fully associative, 16 entries'),
   0x70: ('Cache', 'Trace cache: 12 K-μop, 8-way set associative'),
   0x71: ('Cache', 'Trace cache: 16 K-μop, 8-way set associative'),
   0x72: ('Cache', 'Trace cache: 32 K-μop, 8-way set associative'),
   0x76: ('TLB', 'Instruction TLB: 2M/4M pages, fully associative, 8 entries'),
   0x78: ('Cache', '2nd-level cache: 1 MByte, 4-way set associative, 64byte line size'),
   0x79: ('Cache', '2nd-level cache: 128 KByte, 8-way set associative, 64 byte line size, 2 lines per sector'),
   0x7A: ('Cache', '2nd-level cache: 256 KByte, 8-way set associative, 64 byte line size, 2 lines per sector'),
   0x7B: ('Cache', '2nd-level cache: 512 KByte, 8-way set associative, 64 byte line size, 2 lines per sector'),
   0x7C: ('Cache', '2nd-level cache: 1 MByte, 8-way set associative, 64 byte line size, 2 lines per sector'),
   0x7D: ('Cache', '2nd-level cache: 2 MByte, 8-way set associative, 64byte line size'),
   0x7F: ('Cache', '2nd-level cache: 512 KByte, 2-way set associative, 64-byte line size'),
   0x80: ('Cache', '2nd-level cache: 512 KByte, 8-way set associative, 64-byte line size'),
   0x82: ('Cache', '2nd-level cache: 256 KByte, 8-way set associative, 32 byte line size'),
   0x83: ('Cache', '2nd-level cache: 512 KByte, 8-way set associative, 32 byte line size'),
   0x84: ('Cache', '2nd-level cache: 1 MByte, 8-way set associative, 32 byte line size'),
   0x85: ('Cache', '2nd-level cache: 2 MByte, 8-way set associative, 32 byte line size'),
   0x86: ('Cache', '2nd-level cache: 512 KByte, 4-way set associative, 64 byte line size'),
   0x87: ('Cache', '2nd-level cache: 1 MByte, 8-way set associative, 64 byte line size'),
   0xA0: ('DTLB', 'DTLB: 4k pages, fully associative, 32 entries'),
   0xB0: ('TLB', 'Instruction TLB: 4 KByte pages, 4-way set associative, 128 entries'),
   0xB1: ('TLB', 'Instruction TLB: 2M pages, 4-way, 8 entries or 4M pages, 4-way, 4 entries'),
   0xB2: ('TLB', 'Instruction TLB: 4KByte pages, 4-way set associative, 64 entries'),
   0xB3: ('TLB', 'Data TLB: 4 KByte pages, 4-way set associative, 128 entries'),
   0xB4: ('TLB', 'Data TLB1: 4 KByte pages, 4-way associative, 256 entries'),
   0xB5: ('TLB', 'Instruction TLB: 4KByte pages, 8-way set associative, 64 entries'),
   0xB6: ('TLB', 'Instruction TLB: 4KByte pages, 8-way set associative, 128 entries'),
   0xBA: ('TLB', 'Data TLB1: 4 KByte pages, 4-way associative, 64 entries'),
   0xC0: ('TLB', 'Data TLB: 4 KByte and 4 MByte pages, 4-way associative, 8 entries'),
   0xC1: ('STLB', 'Shared 2nd-Level TLB: 4 KByte/2MByte pages, 8-way associative, 1024 entries'),
   0xC2: ('DTLB', 'DTLB: 4 KByte/2 MByte pages, 4-way associative, 16 entries'),
   0xC3: ('STLB', 'Shared 2nd-Level TLB: 4 KByte /2 MByte pages, 6-way associative, 1536 entries. Also 1GBbyte pages, 4-way, 16 entries.'),
   0xC4: ('DTLB', 'DTLB: 2M/4M Byte pages, 4-way associative, 32 entries'),
   0xCA: ('STLB', 'Shared 2nd-Level TLB: 4 KByte pages, 4-way associative, 512 entries'),
   0xD0: ('Cache', '3rd-level cache: 512 KByte, 4-way set associative, 64 byte line size'),
   0xD1: ('Cache', '3rd-level cache: 1 MByte, 4-way set associative, 64 byte line size'),
   0xD2: ('Cache', '3rd-level cache: 2 MByte, 4-way set associative, 64 byte line size'),
   0xD6: ('Cache', '3rd-level cache: 1 MByte, 8-way set associative, 64 byte line size'),
   0xD7: ('Cache', '3rd-level cache: 2 MByte, 8-way set associative, 64 byte line size'),
   0xD8: ('Cache', '3rd-level cache: 4 MByte, 8-way set associative, 64 byte line size'),
   0xDC: ('Cache', '3rd-level cache: 1.5 MByte, 12-way set associative, 64 byte line size'),
   0xDD: ('Cache', '3rd-level cache: 3 MByte, 12-way set associative, 64 byte line size'),
   0xDE: ('Cache', '3rd-level cache: 6 MByte, 12-way set associative, 64 byte line size'),
   0xE2: ('Cache', '3rd-level cache: 2 MByte, 16-way set associative, 64 byte line size'),
   0xE3: ('Cache', '3rd-level cache: 4 MByte, 16-way set associative, 64 byte line size'),
   0xE4: ('Cache', '3rd-level cache: 8 MByte, 16-way set associative, 64 byte line size'),
   0xEA: ('Cache', '3rd-level cache: 12MByte, 24-way set associative, 64 byte line size'),
   0xEB: ('Cache', '3rd-level cache: 18MByte, 24-way set associative, 64 byte line size'),
   0xEC: ('Cache', '3rd-level cache: 24MByte, 24-way set associative, 64 byte line size'),
   0xF0: ('Prefetch', '64-Byte prefetching'),
   0xF1: ('Prefetch', '128-Byte prefetching'),
   0xFE: ('General', 'CPUID leaf 2 does not report TLB descriptor information; use CPUID leaf 18H to query TLB and other address translation parameters.'),
   0xFF: ('General', 'CPUID leaf 2 does not report cache descriptor information, use CPUID leaf 4 to query cache parameters')
}

# 0xAABBCCDD -> [0xDD, 0xCC, 0xBB, 0xAA]
def get_bytes(reg):
   return [((reg >> s) & 0xFF) for s in range(0, 32, 8)]

def get_bit(reg, bit):
   return (reg >> bit) & 1

# Returns the bits between the indexes start and end (inclusive); start must be <= end
def get_bits(reg, start, end):
   return (reg >> start) & ((1 << (end-start+1)) - 1)


def get_cache_info(cpu):
   vendor = cpu_vendor(cpu)

   cacheInfo = dict()

   if vendor == 'GenuineIntel':
      log.info('\nCPUID Leaf 2 information:')

      a, b, c, d = cpu(0x02)
      for ri, reg in enumerate([a, b, c, d]):
         if (reg >> 31): continue # register is reserved

         for bi, byte in enumerate(get_bytes(reg)):
            if (ri == 0) and (bi == 0): continue # least-significant byte in EAX
            if byte == 0: continue # Null descriptor

            log.info('  - ' + leaf2_descriptors[byte][1])

      log.info('\nCPUID Leaf 4 information:')

      index = 0
      while (True):
         a, b, c, d = cpu(0x04, index)

         cacheType = ''
         bits3_0 = get_bits(a, 0, 3)

         if bits3_0 == 0: break
         if bits3_0 == 1: cacheType = 'Data Cache'
         if bits3_0 == 2: cacheType = 'Instruction Cache'
         if bits3_0 == 3: cacheType = 'Unified Cache'

         level = get_bits(a, 5, 7)
         log.info('  Level ' + str(level) + ' (' + cacheType + '):')

         parameters = []
         if get_bit(a, 8): parameters.append('Self Initializing cache level (does not need SW initialization)')
         if get_bit(a, 9): parameters.append('Fully Associative cache')

         parameters.append('Maximum number of addressable IDs for logical processors sharing this cache: ' + str(get_bits(a, 14, 25)+1))
         parameters.append('Maximum number of addressable IDs for processor cores in the physical package: ' + str(get_bits(a, 26, 31)+1))
         L = int(get_bits(b, 0, 11)+1)
         P = int(get_bits(b, 12, 21)+1)
         W = int(get_bits(b, 22, 31)+1)
         S = int(c+1)
         parameters.append('System Coherency Line Size (L): ' + str(L) + ' B')
         parameters.append('Physical Line partitions (P): ' + str(P))
         parameters.append('Ways of associativity (W): ' + str(W))
         parameters.append('Number of Sets (S): ' + str(S))
         parameters.append('Cache Size: ' + str(W*P*L*S//1024) + ' kB')

         if get_bit(d, 0): parameters.append('WBINVD/INVD is not guaranteed to act upon lower level caches of non-originating threads sharing this cache')
         else: parameters.append('WBINVD/INVD from threads sharing this cache acts upon lower level caches for threads sharing this cache')

         if get_bit(d, 1): parameters.append('Cache is inclusive of lower cache levels')
         else: parameters.append('Cache is not inclusive of lower cache levels')

         complexAddressing = False
         if get_bit(d, 2):
            complexAddressing = True
            parameters.append('A complex function is used to index the cache, potentially using all address bits')

         cacheInfo['L' + str(level) + (cacheType[0] if cacheType[0] in ['D', 'I'] else '')] = {
            'lineSize': L,
            'nSets': S,
            'assoc': W,
            'complex': complexAddressing
         }

         for par in parameters:
            log.info('    - ' + par)

         index += 1
   elif vendor == 'AuthenticAMD':
      _, _, c, d = cpu(0x80000005)

      L1DcLineSize = int(get_bits(c, 0, 7))
      L1DcLinesPerTag = int(get_bits(c, 8, 15))
      L1DcAssoc = int(get_bits(c, 16, 23))
      L1DcSize = int(get_bits(c, 24, 31))

      log.info('  L1DcLineSize: ' + str(L1DcLineSize) + ' B')
      log.info('  L1DcLinesPerTag: ' + str(L1DcLinesPerTag))
      log.info('  L1DcAssoc: ' + str(L1DcAssoc))
      log.info('  L1DcSize: ' + str(L1DcSize) + ' kB')

      cacheInfo['L1D'] = {
         'lineSize': L1DcLineSize,
         'nSets': L1DcSize*1024//L1DcAssoc//L1DcLineSize,
         'assoc': L1DcAssoc
      }

      L1IcLineSize = int(get_bits(d, 0, 7))
      L1IcLinesPerTag = int(get_bits(d, 8, 15))
      L1IcAssoc = int(get_bits(d, 16, 23))
      L1IcSize = int(get_bits(d, 24, 31))

      log.info('  L1IcLineSize: ' + str(L1IcLineSize) + ' B')
      log.info('  L1IcLinesPerTag: ' + str(L1IcLinesPerTag))
      log.info('  L1IcAssoc: ' + str(L1IcAssoc))
      log.info('  L1IcSize: ' + str(L1IcSize) + ' kB')

      cacheInfo['L1I'] = {
         'lineSize': L1IcLineSize,
         'nSets': L1IcSize*1024//L1IcAssoc//L1IcLineSize,
         'assoc': L1IcAssoc
      }

      _, _, c, d = cpu(0x80000006)

      L2LineSize = int(get_bits(c, 0, 7))
      L2LinesPerTag = int(get_bits(c, 8, 11))
      L2Size = int(get_bits(c, 16, 31))
      L2Assoc = 0
      c_15_12 = get_bits(c, 12, 15)
      if c_15_12 == 0x1: L2Assoc = 1
      elif c_15_12 == 0x2: L2Assoc = 2
      elif c_15_12 == 0x4: L2Assoc = 4
      elif c_15_12 == 0x6: L2Assoc = 8
      elif c_15_12 == 0x8: L2Assoc = 16
      elif c_15_12 == 0xA: L2Assoc = 32
      elif c_15_12 == 0xB: L2Assoc = 48
      elif c_15_12 == 0xC: L2Assoc = 64
      elif c_15_12 == 0xD: L2Assoc = 96
      elif c_15_12 == 0xE: L2Assoc = 128
      elif c_15_12 == 0x2: L2Assoc = L2Size*1024//L2LineSize

      log.info('  L2LineSize: ' + str(L2LineSize) + ' B')
      log.info('  L2LinesPerTag: ' + str(L2LinesPerTag))
      log.info('  L2Assoc: ' + str(L2Assoc))
      log.info('  L2Size: ' + str(L2Size) + ' kB')

      cacheInfo['L2'] = {
         'lineSize': L2LineSize,
         'nSets': L2Size*1024//L2Assoc//L2LineSize,
         'assoc': L2Assoc
      }

      L3LineSize = int(get_bits(d, 0, 7))
      L3LinesPerTag = int(get_bits(d, 8, 11))
      L3Size = int(get_bits(d, 18, 31)*512)
      L3Assoc = 0
      d_15_12 = get_bits(d, 12, 15)
      if d_15_12 == 0x1: L3Assoc = 1
      elif d_15_12 == 0x2: L3Assoc = 2
      elif d_15_12 == 0x4: L3Assoc = 4
      elif d_15_12 == 0x6: L3Assoc = 8
      elif d_15_12 == 0x8: L3Assoc = 16
      # Value 0x9, returned by Zen 3, is reserved according to AMD CPUID Specification document.
      # The Software Optimization Guide for AMD Family 19h Processors specifies L3 cache to be 16-way associative and shared by 8 cores inside a CPU complex.
      elif d_15_12 == 0x9: L3Assoc = 16
      elif d_15_12 == 0xA: L3Assoc = 32
      elif d_15_12 == 0xB: L3Assoc = 48
      elif d_15_12 == 0xC: L3Assoc = 64
      elif d_15_12 == 0xD: L3Assoc = 96
      elif d_15_12 == 0xE: L3Assoc = 128

      log.info('  L3LineSize: ' + str(L3LineSize) + ' B')
      log.info('  L3LinesPerTag: ' + str(L3LinesPerTag))
      log.info('  L3Assoc: ' + str(L3Assoc))
      log.info('  L3Size: ' + str(L3Size//1024) + ' MB')

      cacheInfo['L3'] = {
         'lineSize': L3LineSize,
         'nSets': L3Size*1024//L3Assoc//L3LineSize,
         'assoc': L3Assoc
      }

   return cacheInfo

def get_basic_info(cpu):
    strs = ['Vendor: ' + cpu_vendor(cpu)]
    strs += ['CPU Name: ' + cpu_name(cpu)]
    vi = version_info(cpu)
    strs += ['Family: 0x%02X' % vi.displ_family]
    strs += ['Model: 0x%02X' % vi.displ_model]
    strs += ['Stepping: 0x%X' % vi.stepping]
    if vi.core_type:
       strs += ['Core Type: 0x%X' % vi.core_type]
    strs += ['Microarchitecture: ' + micro_arch(cpu)]
    return '\n'.join(strs)

if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, format='%(message)s', level=logging.INFO)
    cpuid = CPUID()

    def valid_inputs():
        for eax in (0x0, 0x80000000):
            highest, _, _, _ = cpuid(eax)
            while eax <= highest:
                regs = cpuid(eax)
                yield (eax, regs)
                eax += 1

    print(' '.join(x.ljust(8) for x in ('CPUID', 'A', 'B', 'C', 'D')).strip())
    for eax, regs in valid_inputs():
        print('%08x' % eax, ' '.join('%08x' % reg for reg in regs))

    print('')
    print(get_basic_info(cpuid))

    print('\nCache information:')
    get_cache_info(cpuid)


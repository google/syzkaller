#!/usr/bin/env python3
import argparse
import os
import io
import subprocess
import glob
import re
from pathlib import Path
from os.path import dirname, abspath


def collect_all_syscalls(freebsd_path, syscalls):
    # Find all FreeBSD system calls
    p1 = subprocess.Popen(["awk", '/#define/{ print $2 }', f'{freebsd_path}/sys/sys/syscall.h'], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(["cut", '-d', '_', '-f', '2-'], stdin=p1.stdout, stdout=subprocess.PIPE)
    p1.stdout.close()
    for syscall in io.TextIOWrapper(p2.stdout, encoding='utf-8'):
        syscalls.add(syscall[:-1])
    p2.stdout.close()

def collect_all_ioctls(freebsd_path, ioctls):
    # Find all pseudo FreeBSD system calls (ioctls)
    for path in Path(freebsd_path).rglob('*.h'):
        with io.open(path, 'r', encoding='utf-8', errors='ignore') as header:
            for line in header:
                prog = re.match(r'^#define\s+(.*)\s+.*_IOW?R?\(.*\)', line)
                if prog:
                    ioctls.add(prog[1])

def collect_implemented_syscalls(implemented_syscalls):
    # Find implemented system calls in Syzkaller
    for path in glob.glob("*.txt"):
        with open(path, 'r') as reader:
            for line in reader:
                prog = re.match(r'(\w+)[$(]', line)
                if prog:
                    implemented_syscalls.add(prog[1])

def collect_implemented_ioctls(implemented_ioctls):
    # Find implemented ioctls in Syzkaller
    for path in glob.glob("*.txt"):
        with open(path, 'r') as reader:
            for line in reader:
                io = re.match(r'ioctl\$(\w+)\(', line)
                if io:
                    implemented_ioctls.add(io[1])

def output_syscall_results(syscalls, implemented_syscalls):
    # Output missing system calls or ioctls
    diff = sorted(syscalls.difference(implemented_syscalls))
    print(f'****Syscalls: {len(diff)}****')
    for missing_syscall in diff:
        print(missing_syscall)

def output_ioctl_results(ioctls, implemented_ioctls):
    # Output missing system calls or ioctls
    diff = sorted(ioctls.difference(implemented_ioctls))
    print(f'****Ioctls: {len(diff)}****')
    for missing_syscall in diff:
        print(missing_syscall)

def main():
    parser = argparse.ArgumentParser(prog='freebsd_missing_syscall_checker', description='Prints missing FreeBSD syscalls.')
    parser.add_argument('-s', '--syscall', action='store_true', help='Print missing syscalls.')
    parser.add_argument('-i', '--ioctl', action='store_true', help='Print missing ioctls.')
    parser.add_argument('-p', '--path', required=True, help='Path of FreeBSD src checkout.')
    args = parser.parse_args()

    if not(args.syscall or args.ioctl):
        parser.error('No action requested, add -s or -i.')

    os.chdir(dirname(dirname(abspath(__file__))) + '/sys/freebsd')
    if args.syscall:
        syscalls = set()
        implemented_syscalls = set()
        collect_all_syscalls(args.path, syscalls)
        collect_implemented_syscalls(implemented_syscalls)
        output_syscall_results(syscalls, implemented_syscalls)
    if args.ioctl:
        ioctls = set()
        implemented_ioctls = set()
        collect_all_ioctls(args.path, ioctls)
        collect_implemented_ioctls(implemented_ioctls)
        output_ioctl_results(ioctls, implemented_ioctls)

if __name__ == "__main__":
    main()

#!/usr/bin/python3

import argparse

from io import TextIOWrapper
from os import listxattr, path, stat, walk
from stat import S_ISUID

DESCRIPTION = 'Utility to create audit privilege rules based on given path.'
FILE_CAP_XATTR = 'security.capability'
USER_ID_MIN = 900
ARCH64 = 'b64'
ARCH32 = 'b32'


def file_has_capability(target: str) -> bool:
    return FILE_CAP_XATTR in listxattr(target)


def file_has_setuid_bit(target: str) -> bool:
    return stat(target).st_mode & S_ISUID


def audit_entry_string(target: str, arch: str) -> str:
    return (
        '-a always,exit '
        f'-F arch={arch} '
        f'-F path={target} '
        '-F perm=x '
        f'-F auid>={USER_ID_MIN} -F auid!=unset '
        '-F key=privileged\n'
    )


def write_audit_entry(target: str, fh: TextIOWrapper) -> None:
    fh.write(audit_entry_string(target, ARCH64))
    fh.write(audit_entry_string(target, ARCH32))


def generate_audit_privilege(target_dir: str, privilege_file: str) -> None:
    with open(privilege_file, 'w') as f:
        for root, dirs, files in walk(target_dir):
            for name in files:
                target = path.join(root, name)
                try:
                    if file_has_setuid_bit(target) or file_has_capability(target):
                        write_audit_entry(target, f)
                except FileNotFoundError:
                    # possibly broken symlink
                    pass

        f.flush()


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        '-t', '--target_dir',
        help='Target directory in which to find privileged files.'
    )
    parser.add_argument(
       '-p', '--privilege_file',
       help='File in which to write privilege rules.'
    )

    args = parser.parse_args()
    generate_audit_privilege(args.target_dir, args.privilege_file)


if __name__ == '__main__':
    main()

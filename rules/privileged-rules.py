#!/usr/bin/python3

import argparse
import errno
import sys

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


def __strip_prefix(target: str, prefix: str) -> str:
    return target[len(prefix):]


def audit_entry_string(target: str, arch: str, prefix: str) -> str:
    return (
        '-a always,exit '
        f'-F arch={arch} '
        f'-F path={__strip_prefix(target, prefix)} '
        '-F perm=x '
        f'-F auid>={USER_ID_MIN} -F auid!=unset '
        '-F key=privileged\n'
    )


def write_audit_entry(target: str, fh: TextIOWrapper, prefix: str) -> None:
    fh.write(audit_entry_string(target, ARCH64, prefix))
    fh.write(audit_entry_string(target, ARCH32, prefix))


def generate_audit_privilege(target_dir: str, privilege_file: str, prefix: str) -> None:
    if prefix and not target_dir.startswith(prefix):
        raise ValueError(f'{target_dir}: target_dir does not start with prefix [{prefix}]')

    with open(privilege_file, 'w') as f:
        for root, dirs, files in walk(target_dir):
            for name in files:
                target = path.join(root, name)
                try:
                    if file_has_setuid_bit(target) or file_has_capability(target):
                        write_audit_entry(target, f, prefix)
                except FileNotFoundError:
                    pass  # possibly broken symlink
                except OSError as os_e:
                    if os_e.errno == errno.ELOOP:
                        pass  # avoid circular link
                    else:
                        print(f"Detected unhandled OSError in auditd privileged rule file generation: {os_e}", file=sys.stderr)
                except Exception as e:
                    # Unexpected error.  Skip this file, but record the event.
                    print(f"Detected error in auditd privileged rule file generation: {e}", file=sys.stderr)

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
    parser.add_argument(
        '-x', '--prefix',
        help='File in which to write privilege rules.',
        default=''
    )

    args = parser.parse_args()

    generate_audit_privilege(args.target_dir, args.privilege_file, args.prefix)


if __name__ == '__main__':
    main()

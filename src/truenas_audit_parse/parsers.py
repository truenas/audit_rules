# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

import truenas_auparse
from types import MappingProxyType

from .constants import AUDITD_NULL_VALUES, PAM_MSG_TYPES, SERVICE_MSG_TYPES
from .event_types import AuditEvent, AuditMsgEventType


def parse_multipart_event(raw_lines: list[str]) -> dict:
    """Parse multiple audit record lines into a structured dict using libauparse.

    Joins lines with newlines and feeds them to the C extension for parsing.

    Returns:
        dict with 'records' key containing list of parsed record dicts.
    """
    combined = '\n'.join(raw_lines)
    return truenas_auparse.parse_event(combined)


def classify_event(parsed: dict) -> AuditEvent:
    """Determine the AuditEvent type from parsed records.

    Reads the 'key' field from SYSCALL records, or determines type from
    LOGIN, SERVICE, PAM, or TTY records.
    """
    for record in parsed.get('records', []):
        type_name = record.get('type_name', '')
        fields = record.get('fields', {})

        if type_name == AuditMsgEventType.SYSCALL:
            key = fields.get('key')
            if key is None or key in AUDITD_NULL_VALUES:
                return AuditEvent.GENERIC
            try:
                return AuditEvent(key)
            except ValueError:
                return AuditEvent.GENERIC

        if type_name == AuditMsgEventType.LOGIN:
            return AuditEvent.LOGIN

        if type_name in SERVICE_MSG_TYPES:
            return AuditEvent.SERVICE

        if type_name in PAM_MSG_TYPES:
            return AuditEvent.CREDENTIAL

        if type_name == AuditMsgEventType.TTY:
            return AuditEvent.TTY_RECORD

    return AuditEvent.GENERIC


def _null_if_empty(value: str | None) -> str | None:
    """Convert auditd null-equivalent strings to None."""
    if value is None or value in AUDITD_NULL_VALUES:
        return None
    return value


def _raw_int(raw_fields: dict, key: str) -> int | None:
    """Get a raw field value as int, returning None on failure."""
    value = raw_fields.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _to_bool_success(value: str | None) -> bool:
    """Convert success field to boolean."""
    if value is None:
        return False
    return value.lower() in ('yes', 'success', '1')


def process_syscall(fields: dict, raw_fields: dict | None = None) -> dict:
    """Post-process SYSCALL record fields for TNAUDIT output.

    Matches the old handler's AuditMsgSyscall field subset:
    success, exit, ppid, pid, auid, uid, gid, euid, suid, fsuid,
    egid, sgid, fsgid, tty, ses, key, SYSCALL, AUID, UID, GID
    """
    if raw_fields is None:
        raw_fields = {}

    result = {}

    # Bool field
    if 'success' in fields:
        result['success'] = _to_bool_success(fields['success'])

    # Int fields from raw values (old handler used positional raw extraction)
    for k in ('exit', 'ppid', 'pid', 'auid', 'uid', 'gid',
              'euid', 'suid', 'fsuid', 'egid', 'sgid', 'fsgid',
              'ses'):
        if k in fields:
            result[k] = _raw_int(raw_fields, k)

    # String fields
    if 'tty' in fields:
        result['tty'] = _null_if_empty(fields['tty'])
    if 'key' in fields:
        result['key'] = _null_if_empty(fields['key'])

    # Interpreted uppercase fields (old handler extracted these by position)
    for k in ('SYSCALL', 'AUID', 'UID', 'GID'):
        if k in fields:
            result[k] = _null_if_empty(fields[k])

    return result


def process_path(fields: dict, raw_fields: dict | None = None) -> dict:
    """Post-process PATH record fields for TNAUDIT output.

    Matches the old handler's AuditMsgPath field subset:
    name, inode, dev, mode, ouid, ogid, rdev, nametype
    """
    if raw_fields is None:
        raw_fields = {}

    result = {}

    # String fields (use raw for mode to preserve octal format)
    if 'name' in fields:
        result['name'] = _null_if_empty(fields['name'])
    if 'dev' in fields:
        result['dev'] = _null_if_empty(raw_fields.get('dev', fields.get('dev')))
    if 'mode' in fields:
        result['mode'] = _null_if_empty(raw_fields.get('mode', fields.get('mode')))
    if 'rdev' in fields:
        result['rdev'] = _null_if_empty(raw_fields.get('rdev', fields.get('rdev')))
    if 'nametype' in fields:
        result['nametype'] = _null_if_empty(fields['nametype'])

    # Int fields from raw
    if 'inode' in fields:
        result['inode'] = _raw_int(raw_fields, 'inode')
    if 'ouid' in fields:
        result['ouid'] = _raw_int(raw_fields, 'ouid')
    if 'ogid' in fields:
        result['ogid'] = _raw_int(raw_fields, 'ogid')

    return result


def process_login(fields: dict, raw_fields: dict | None = None) -> dict:
    """Post-process LOGIN record fields for TNAUDIT output.

    Matches the old handler's AuditMsgLogin field subset:
    old-auid, auid, tty, old-ses, ses, res
    """
    if raw_fields is None:
        raw_fields = {}

    result = {}
    for k in ('old-auid', 'auid', 'old-ses', 'ses', 'res'):
        if k in fields:
            result[k] = _raw_int(raw_fields, k)
    if 'tty' in fields:
        result['tty'] = _null_if_empty(fields['tty'])

    return result


def process_service(fields: dict, raw_fields: dict | None = None) -> dict:
    """Post-process SERVICE_START/SERVICE_STOP record fields.

    Matches the old handler's AuditMsgService field subset:
    subj, unit, comm, exe, res
    """
    result = {}
    if 'subj' in fields:
        result['subj'] = _null_if_empty(fields['subj'])
    if 'unit' in fields:
        result['unit'] = _null_if_empty(fields['unit'])
    if 'comm' in fields:
        result['comm'] = _null_if_empty(fields['comm'])
    if 'exe' in fields:
        result['exe'] = _null_if_empty(fields['exe'])
    if 'res' in fields:
        result['res'] = _to_bool_success(fields['res'])
    return result


def process_pam(fields: dict, raw_fields: dict | None = None) -> dict:
    """Post-process PAM-related record fields (USER_*, CRED_*).

    Matches the old handler's PAM field subset:
    pid, function, grantors, acct, exe, hostname, addr, terminal, res, username
    """
    if raw_fields is None:
        raw_fields = {}

    result = {}

    if 'pid' in fields:
        result['pid'] = _raw_int(raw_fields, 'pid')

    # Old handler called this 'function', auparse calls it 'op'
    if 'op' in fields:
        result['function'] = _null_if_empty(fields['op'])

    for k in ('grantors', 'acct', 'exe', 'hostname', 'terminal'):
        if k in fields:
            result[k] = _null_if_empty(fields[k])

    if 'addr' in fields:
        result['addr'] = _null_if_empty(fields['addr'])

    if 'res' in fields:
        result['res'] = _to_bool_success(fields['res'])

    # AUID → username (old handler mapped AUID key to 'username')
    if 'AUID' in fields:
        result['username'] = _null_if_empty(fields['AUID'])

    return result


def process_tty(fields: dict, raw_fields: dict | None = None) -> dict:
    """Post-process TTY record fields."""
    if raw_fields is None:
        raw_fields = {}

    result = {}
    for k in ('pid', 'uid', 'ses', 'major', 'minor'):
        if k in fields:
            result[k] = _raw_int(raw_fields, k)
    if 'comm' in fields:
        result['comm'] = _null_if_empty(fields['comm'])
    if 'data' in fields:
        result['data'] = _null_if_empty(fields['data'])
    # Old handler mapped AUID_STR to 'username'
    if 'AUID' in fields:
        result['username'] = _null_if_empty(fields['AUID'])

    return result


RECORD_PROCESSORS = MappingProxyType({
    AuditMsgEventType.SYSCALL: process_syscall,
    AuditMsgEventType.PATH: process_path,
    AuditMsgEventType.LOGIN: process_login,
    AuditMsgEventType.SERVICE_START: process_service,
    AuditMsgEventType.SERVICE_STOP: process_service,
    AuditMsgEventType.TTY: process_tty,
    AuditMsgEventType.USER_START: process_pam,
    AuditMsgEventType.USER_END: process_pam,
    AuditMsgEventType.USER_ACCT: process_pam,
    AuditMsgEventType.USER_AUTH: process_pam,
    AuditMsgEventType.USER_LOGIN: process_pam,
    AuditMsgEventType.USER_ERR: process_pam,
    AuditMsgEventType.CRED_ACQ: process_pam,
    AuditMsgEventType.CRED_REFR: process_pam,
    AuditMsgEventType.CRED_DISP: process_pam,
})

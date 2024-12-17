from codecs import decode
from datetime import datetime
from json import dumps
from random import getrandbits
from uuid import UUID
from .constants import (
    AUDITEntry,
    AuditEvent,
    AuditCwdOffset,
    AuditMsgOffset,
    AuditPathOffset,
    AuditProctitleOffset,
    AuditSyscallOffset,
    MULTIPART_EVENT
)


def __get_value(keystr: str):
    return keystr.split('=')[1]


def get_msg_id(parts: list[str]) -> str:
    msg_id = parts[AuditMsgOffset.MSGID]
    # We need to strip of trailing colon (:) from field value
    return __get_value(msg_id)[0:-1]


def get_msg_type(parts: list[str]) -> str:
    msgtype = parts[AuditMsgOffset.TYPE]
    return __get_value(msgtype)


def get_audit_event(parts: list[str]) -> AuditEvent | None:
    # only syscall events will have the key loaded
    if get_msg_type(parts) != 'SYSCALL':
        return None

    if (key := __get_value(parts[AuditSyscallOffset.KEY])) == '(null)':
        return AuditEvent.GENERIC

    return AuditEvent(key.strip('"'))


def entry_type_is_multipart(entry_type: str) -> bool:
    return entry_type in MULTIPART_EVENT


def __parse_cwd(msg_parts: list, event_data: dict) -> None:
    event_data['cwd'] = __get_value(msg_parts[AuditCwdOffset.CWD])


def __parse_path(msg_parts: list, paths: list) -> None:
    path_entry = {}

    # deliberately leave off the item number from the line since it
    # can be inferred from array index.
    for item in msg_parts[AuditPathOffset.NAME:]:
        key, val = item.split('=')
        path_entry[key] = val

    paths.append(path_entry)


def __parse_proctitle(msg_parts: list, event_data: dict) -> None:
    pstr = __get_value(msg_parts[AuditProctitleOffset.PROCTITLE])
    event_data['proctitle'] = decode(pstr, 'hex').decode().replace('\x00', ' ')


SYSCALL_FIELDS = (
    # offset, is an integer
    (AuditSyscallOffset.SUCCESS, False),
    (AuditSyscallOffset.EXIT, True),
    (AuditSyscallOffset.PPID, True),
    (AuditSyscallOffset.PID, True),
    (AuditSyscallOffset.AUID, True),
    (AuditSyscallOffset.UID, True),
    (AuditSyscallOffset.GID, True),
    (AuditSyscallOffset.EUID, True),
    (AuditSyscallOffset.SUID, True),
    (AuditSyscallOffset.FSUID, True),
    (AuditSyscallOffset.EGID, True),
    (AuditSyscallOffset.SGID, True),
    (AuditSyscallOffset.FSGID, True),
    (AuditSyscallOffset.TTY, False),
    (AuditSyscallOffset.SES, True),
    (AuditSyscallOffset.SYSCALL_STR, False),
)


def __parse_syscall(msg_parts: list, event_data: dict) -> None:
    if event_data['syscall'] is not None:
        return

    event_data['syscall'] = {}

    for field_offset, is_int in SYSCALL_FIELDS:
        key, value = msg_parts[field_offset].split('=')
        event_data['syscall'][key] = int(value) if is_int else value


def __parse_raw_msg(msg: str, event_data: dict):
    # We can include inferred items in our entry
    parts = msg.split()

    match get_msg_type(parts):
        case 'PATH':
            return __parse_path(parts, event_data['paths'])
        case 'PROCTITLE':
            return __parse_proctitle(parts, event_data)
        case 'CWD':
            return __parse_cwd(parts, event_data)
        case 'SYSCALL':
            return __parse_syscall(parts, event_data)
        case _:
            pass


def __generate_event_data(
    entry: AUDITEntry,
    data_out: dict
) -> None:

    data_out['event'] = data_out['event'].upper()

    if entry.key_event:
        user_field = entry.key_event[AuditSyscallOffset.UID_STR]
        data_out['user'] = __get_value(user_field)
        success_field = entry.key_event[AuditSyscallOffset.SUCCESS]
        data_out['success'] = __get_value(success_field) == 'yes'

    for item in entry.raw_lines:
        __parse_raw_msg(item, data_out['event_data'])


def __parse_msgid(msgid: str, entry_data: dict):
    """
    msgid is string such as audit(1734419821.939:3615). The part before the `:`
    character is a timestamp and the part after it is the audit event id.
    We need to convert this string into a UUID for the audit event.

    Unfortunately the audit event id is only an unsigned int, and so it's not
    actually universally unique and potentialy not unique over time.

    We convert this into a UUID by moving the timestamp to upper 64 bits of a
    128 bit integer, using the audit event id as the bottom 32 bits, and then
    placing random 32 bits in the middle of it.
    """
    msgid = msgid.split('(')[1].strip(')')
    timestamp, eventid = msgid.split(':')
    ts_datetime = datetime.fromtimestamp(float(timestamp))

    upper_64 = int(timestamp.replace('.', '')) << 64
    lower_32 = int(eventid)
    mid_32 = getrandbits(32) << 32

    entry_data['time'] = ts_datetime.strftime('%Y-%m-%d %H:%M:%S.%f')
    entry_data['aid'] = str(UUID(int=upper_64 + lower_32 + mid_32))


def audit_entry_to_json(msgid: str, entry: AUDITEntry) -> str:
    to_write = {'TNAUDIT': {
        'aid': None,
        'vers': {'major': 0, 'minor': 1},
        'addr': '127.0.0.1',
        'user': None,
        'sess': None,
        'time': None,
        'svc': 'SYSTEM_AUDIT',
        'svc_data': None,  # per our NEP None is OK here
        'event': entry.event_type or AuditEvent.GENERIC,
        'event_data': {
            'audit_msg_id_str': msgid,
            'proctitle': None,
            'syscall': None,
            'cwd': None,
            'paths': [],
            'raw_lines': entry.raw_lines
        },
        'success': True
    }}

    __parse_msgid(msgid, to_write['TNAUDIT'])
    __generate_event_data(entry, to_write['TNAUDIT'])

    return '@cee:' + dumps(to_write)

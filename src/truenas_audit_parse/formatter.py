# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

from datetime import datetime
from json import dumps
from random import getrandbits
from uuid import UUID

from .constants import AUDITD_NULL_VALUES, JSON_NULL
from .event_types import AuditEvent, AuditMsgEventType
from .parsers import (
    classify_event,
    parse_multipart_event,
    RECORD_PROCESSORS,
)


def parse_msgid(msgid: str) -> tuple[str, str]:
    """Parse audit message ID into a UUID and timestamp string.

    msgid is a string such as 'audit(1734419821.939:3615)'. The part before
    the ':' is a timestamp and the part after is the audit event id.

    We convert this into a UUID by placing the timestamp in the upper 64 bits,
    random 32 bits in the middle, and the event id in the lower 32 bits.

    Returns:
        (aid, time_str) tuple
    """
    inner = msgid.split('(')[1].strip(')')
    timestamp, eventid = inner.split(':')
    ts_datetime = datetime.fromtimestamp(float(timestamp))

    upper_64 = int(timestamp.replace('.', '')) << 64
    lower_32 = int(eventid)
    mid_32 = getrandbits(32) << 32

    time_str = ts_datetime.strftime('%Y-%m-%d %H:%M:%S.%f')
    aid = str(UUID(int=upper_64 + lower_32 + mid_32))

    return (aid, time_str)


def _generate_event_data(
    parsed: dict,
    event_type: AuditEvent,
    raw_lines: list[str],
    key_event_parts: list[str] | None,
) -> dict:
    """Build TNAUDIT event_data dict from parsed records.

    Every event arrives fully assembled (auparse groups all records by msgid).
    We iterate the records, apply processors, and build the output dict.
    """
    event_data = {}
    user = None
    success = True
    addr = '127.0.0.1'
    event = event_type or AuditEvent.GENERIC

    for record in parsed.get('records', []):
        type_name = record.get('type_name', '')
        fields = record.get('fields', {})
        raw_fields = record.get('raw_fields', {})

        processor = RECORD_PROCESSORS.get(type_name)
        if processor is not None:
            fields = processor(fields, raw_fields)

        match type_name:
            case AuditMsgEventType.SYSCALL:
                if 'syscall' not in event_data:
                    event_data['syscall'] = fields
                    uid_str = fields.get('UID')
                    if uid_str and uid_str not in AUDITD_NULL_VALUES:
                        user = uid_str
                    if 'success' in fields:
                        success = fields['success']

            case AuditMsgEventType.PATH:
                event_data.setdefault('paths', []).append(fields)

            case AuditMsgEventType.PROCTITLE:
                event_data['proctitle'] = fields.get('proctitle')

            case AuditMsgEventType.CWD:
                event_data['cwd'] = fields.get('cwd')

            case AuditMsgEventType.LOGIN:
                event_data.update(fields)
                event = AuditEvent.LOGIN

            case AuditMsgEventType.SERVICE_START | AuditMsgEventType.SERVICE_STOP:
                event_data['service_action'] = type_name
                event_data.update(fields)
                event = AuditEvent.SERVICE
                if 'res' in fields and isinstance(fields['res'], bool):
                    success = fields['res']

            case AuditMsgEventType.USER_START | AuditMsgEventType.USER_END | \
                 AuditMsgEventType.USER_ACCT | AuditMsgEventType.USER_AUTH | \
                 AuditMsgEventType.USER_LOGIN | AuditMsgEventType.USER_ERR | \
                 AuditMsgEventType.CRED_ACQ | AuditMsgEventType.CRED_REFR | \
                 AuditMsgEventType.CRED_DISP:
                event_data['auth_action'] = type_name
                event_data.update(fields)
                event = AuditEvent.CREDENTIAL
                username = fields.get('username') or fields.get('acct')
                if username:
                    user = username
                addr_val = fields.get('addr')
                if addr_val and addr_val not in AUDITD_NULL_VALUES:
                    addr = addr_val
                if 'res' in fields and isinstance(fields['res'], bool):
                    success = fields['res']

            case AuditMsgEventType.TTY:
                event_data['tty_record'] = fields
                event = AuditEvent.TTY_RECORD
                username = fields.get('username')
                if username and username not in AUDITD_NULL_VALUES:
                    user = username

            case _:
                pass

    # If we have a key_event (SYSCALL with key) and no user yet, extract from it
    if key_event_parts and not user:
        for record in parsed.get('records', []):
            if record.get('type_name') == AuditMsgEventType.SYSCALL:
                uid_str = record.get('fields', {}).get('UID')
                if uid_str:
                    user = uid_str
                break

    return {
        'event': event.upper() if isinstance(event, str) else str(event).upper(),
        'event_data': event_data,
        'user': user,
        'success': success,
        'addr': addr,
    }


def audit_entry_to_json(
    msgid: str,
    event_type: AuditEvent | None,
    raw_lines: list[str],
    key_event_parts: list[str] | None = None,
    parsed: dict | None = None,
) -> str:
    """Build TNAUDIT JSON string from audit entry data.

    Args:
        msgid: The audit message ID string (e.g., 'audit(1734419821.939:3615)')
        event_type: The classified event type, or None for generic
        raw_lines: Raw audit message lines
        key_event_parts: Split parts of the key SYSCALL line, if any
        parsed: Pre-parsed event dict (if None, raw_lines will be parsed)

    Returns:
        '@cee:' prefixed JSON string for syslog
    """
    aid, time_str = parse_msgid(msgid)

    if parsed is None:
        parsed = parse_multipart_event(raw_lines)
    generated = _generate_event_data(parsed, event_type, raw_lines, key_event_parts)

    event_data_dict = generated['event_data']

    # Old handler: only events with a keyed SYSCALL (key_event set) had
    # audit_msg_id_str and raw_lines=None in event_data.
    if key_event_parts is not None:
        event_data_dict['audit_msg_id_str'] = msgid
        event_data_dict['raw_lines'] = None

    to_write = {'TNAUDIT': {
        'aid': aid,
        'vers': {'major': 0, 'minor': 1},
        'addr': generated['addr'],
        'user': generated['user'],
        'sess': None,
        'time': time_str,
        'svc': 'SYSTEM',
        'svc_data': JSON_NULL,
        'event': generated['event'],
        'event_data': dumps(event_data_dict),
        'success': generated['success'],
    }}

    return '@cee:' + dumps(to_write)

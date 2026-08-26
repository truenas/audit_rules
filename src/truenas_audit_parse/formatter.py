# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

from datetime import datetime, timezone
from json import dumps
from random import getrandbits
from uuid import UUID

from .constants import AUDITD_NULL_VALUES, JSON_NULL
from .event_types import AuditEvent, AuditMsgEventType
from .parsers import (
    parse_multipart_event,
    RECORD_PROCESSORS,
)
from .s3 import s3_entry_to_json

# Events the old handler represented with a dedicated single-record parser;
# their event_data carried only their own parsed fields (no audit_msg_id_str /
# raw_lines / proctitle / syscall / cwd / paths superset). Values match the
# upper-cased AuditEvent names emitted in the 'event' field.
_SINGLE_RECORD_EVENTS = frozenset({'LOGIN', 'SERVICE', 'CREDENTIAL', 'TTY_RECORD'})


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
    ts_datetime = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)

    upper_64 = int(timestamp.replace('.', '')) << 64
    lower_32 = int(eventid)
    mid_32 = getrandbits(32) << 32

    time_str = ts_datetime.strftime('%Y-%m-%d %H:%M:%S.%f')
    aid = str(UUID(int=upper_64 + lower_32 + mid_32))

    return (aid, time_str)


def _generate_event_data(
    parsed: dict,
    event_type: AuditEvent,
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
    parsed: dict | None = None,
) -> str:
    """Build TNAUDIT JSON string from audit entry data.

    Args:
        msgid: The audit message ID string (e.g., 'audit(1734419821.939:3615)')
        event_type: The classified event type, or None for generic
        raw_lines: Raw audit message lines
        parsed: Pre-parsed event dict (if None, raw_lines will be parsed)

    Returns:
        '@cee:' prefixed JSON string for syslog
    """
    if parsed is None:
        parsed = parse_multipart_event(raw_lines)

    # The S3 daemon's records are their own service with their own
    # envelope mapping; nothing of the SYSTEM schema below applies.
    if event_type == AuditEvent.S3:
        return s3_entry_to_json(msgid, parsed)

    aid, time_str = parse_msgid(msgid)
    generated = _generate_event_data(parsed, event_type)

    event_data_dict = generated['event_data']

    # Reproduce the old handler's event_data schema. The single-record PAM /
    # LOGIN / SERVICE / TTY events carried only their own parsed fields. Every
    # other event (keyed-SYSCALL and generic) carried a fixed superset of keys
    # plus audit_msg_id_str, with raw_lines collapsed to None whenever the event
    # contained a SYSCALL record and otherwise holding the raw record text.
    if generated['event'] not in _SINGLE_RECORD_EVENTS:
        has_syscall = any(
            record.get('type_name') == AuditMsgEventType.SYSCALL
            for record in parsed.get('records', [])
        )
        event_data_dict.setdefault('proctitle', None)
        event_data_dict.setdefault('syscall', None)
        event_data_dict.setdefault('cwd', None)
        event_data_dict.setdefault('paths', [])
        event_data_dict['audit_msg_id_str'] = msgid
        event_data_dict['raw_lines'] = None if has_syscall else raw_lines

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

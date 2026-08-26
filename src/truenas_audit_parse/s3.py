# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

"""The TrueNAS S3 daemon's audit records, as their own service.

s3d emits one kernel-audit record per audited S3 request (AUDIT.md in
the truenas_s3 repository): TRUSTED_APP for an executed operation,
USER_AUTH for a request refused before a principal existed, USER_ACCT
for an account the identity gate refused, and DAC_CHECK for a
discretionary denial. Every record carries op=s3d:<Operation>, which is
what marks it as S3's — a TRUSTED_APP from any other producer stays on
the generic path.

This module maps such a record onto the TNAUDIT envelope the way the
producer's design specifies: user from acct=, addr from addr=, time
from ts= (the moment the outcome was settled, immune to queue delay),
success from res=, event from the operation in op=, and every other
field into a typed event_data. The service is 'S3', so once middleware
registers it (AUDITED_SERVICES) the events land in /audit/S3.db rather
than inside the SYSTEM trail.
"""

import binascii

from datetime import datetime, timezone
from json import dumps

from .constants import S3_MSG_TYPES, S3_OP_PREFIX

S3_SERVICE = 'S3'
S3_VERS = {'major': 0, 'minor': 1}

# The producer's variable-length string fields, in the order the record
# defines them. Values were libaudit-encoded on the wire and are decoded
# through _decoded() below.
_STR_FIELDS = (
    'req', 'keyid', 'bucket', 'obj', 'ver', 'err',
    'range', 'src_bucket', 'src_obj', 'src_ver',
    'upload', 'prefix',
)

# Numeric fields. libaudit encoding quotes them like any clean value.
_INT_FIELDS = (
    'acct_uid', 'status', 'bytes_in', 'bytes_out', 'size',
    'part', 'parts', 'deleted', 'denied', 'errors', 'n', 'truncated',
)

# Flag fields the producer emits only when true (as "1").
_FLAG_FIELDS = ('marker', 'clipped')


def s3_record(parsed: dict) -> dict | None:
    """The s3d record of an event, or None when the event is not S3's.

    An s3d event is always a single record, but the check tolerates
    company: the first record carrying the op=s3d: vocabulary in one of
    the four types s3d originates is the one.
    """
    for record in parsed.get('records', []):
        if record.get('type_name') not in S3_MSG_TYPES:
            continue
        if record.get('fields', {}).get('op', '').startswith(S3_OP_PREFIX):
            return record
    return None


def _decoded(fields: dict, raw_fields: dict, key: str) -> str | None:
    """A field value with the producer's libaudit encoding undone.

    The producer quotes a clean value and hex-encodes a dirty one
    (spaces, quotes, any byte outside 0x21..0x7e). libauparse dequotes
    the clean form but leaves the hex form untouched for fields outside
    its own dictionary, so the raw field's quoting is the discriminator:
    quoted means the interpreted value stands, unquoted hex decodes.
    Undecodable bytes are replaced rather than dropped — a hostile name
    must not be able to hide a record's field.
    """
    value = fields.get(key)
    if value is None:
        return None
    raw = raw_fields.get(key, '')
    if raw.startswith('"'):
        return value
    if len(value) % 2 == 0 and value:
        try:
            return binascii.unhexlify(value).decode('utf-8', 'replace')
        except (binascii.Error, ValueError):
            pass
    return value


def _s3_time(fields: dict, fallback: str) -> str:
    """The record's own settled timestamp, TNAUDIT-formatted.

    ts= is stamped by the producer when the outcome settled; the audit
    framework's own stamp is send time, and the difference is queue
    delay. Fall back to the message id's timestamp when absent.
    """
    ts = fields.get('ts')
    if ts is None:
        return fallback
    try:
        parsed = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return fallback
    return parsed.strftime('%Y-%m-%d %H:%M:%S.%f')


def _batch_keys(fields: dict, raw_fields: dict) -> list[str]:
    """The delete batch's numbered obj_N fields, in order.

    The producer numbers a field per key because keys may contain any
    byte a list separator could use; here they become the JSON list
    that shape exists to survive as.
    """
    numbered = []
    for key in fields:
        if not key.startswith('obj_'):
            continue
        try:
            index = int(key[len('obj_'):])
        except ValueError:
            continue
        numbered.append((index, key))
    numbered.sort()
    return [_decoded(fields, raw_fields, key) for _, key in numbered]


def process_s3(record: dict) -> dict:
    """Build the S3 event_data from one s3d record.

    Typed per the producer's field sets: strings decoded, counts as
    integers, flags as booleans, the batch's numbered keys as a list.
    The kernel's own prefix fields (pid, uid, auid — the sender's
    identity, not the principal's) stay out; the principal is the
    envelope's user.
    """
    fields = record.get('fields', {})
    raw_fields = record.get('raw_fields', {})

    event_data = {
        'vers': S3_VERS,
        'record_type': record.get('type_name'),
    }
    for key in _STR_FIELDS:
        if key in fields:
            event_data[key] = _decoded(fields, raw_fields, key)
    for key in _INT_FIELDS:
        if key in fields:
            try:
                event_data[key] = int(fields[key])
            except (ValueError, TypeError):
                event_data[key] = None
    for key in _FLAG_FIELDS:
        if key in fields:
            event_data[key] = fields[key] == '1'
    keys = _batch_keys(fields, raw_fields)
    if keys:
        event_data['objs'] = keys

    return event_data


def s3_entry_to_json(msgid: str, parsed: dict) -> str:
    """Build the TNAUDIT JSON string for an s3d event.

    The envelope mapping is mechanical, as the producer's design lays
    out: user from acct=, addr from addr=, time from ts=, success from
    res=, event from the operation in op=, everything else in
    event_data. Callers route the result under the TNAUDIT_S3 syslog
    ident so syslog-ng lands it in the S3 service's own database once
    middleware registers the service.
    """
    # Deferred import: formatter imports this module too, and the
    # msgid parser is the one piece shared in that direction.
    from .formatter import parse_msgid

    record = s3_record(parsed)
    if record is None:
        raise ValueError(f'{msgid}: not an s3d event')
    fields = record.get('fields', {})
    raw_fields = record.get('raw_fields', {})

    aid, msgid_time = parse_msgid(msgid)
    verb = fields.get('op', '')[len(S3_OP_PREFIX):]

    to_write = {'TNAUDIT': {
        'aid': aid,
        'vers': S3_VERS,
        'addr': _decoded(fields, raw_fields, 'addr') or '127.0.0.1',
        'user': _decoded(fields, raw_fields, 'acct'),
        'sess': None,
        'time': _s3_time(fields, msgid_time),
        'svc': S3_SERVICE,
        'svc_data': dumps({'vers': S3_VERS}),
        'event': verb,
        'event_data': dumps(process_s3(record)),
        'success': fields.get('res') == 'success',
    }}

    return '@cee:' + dumps(to_write)

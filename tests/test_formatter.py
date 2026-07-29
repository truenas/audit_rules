# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

import json
import os
import time
from contextlib import contextmanager

from truenas_audit_parse.formatter import parse_msgid, audit_entry_to_json
from truenas_audit_parse.event_types import AuditEvent


SAMPLE_MSGID = 'audit(1734547436.320:852)'
SAMPLE_TIME_UTC = '2024-12-18 18:43:56.320000'


@contextmanager
def local_timezone(name):
    """Run the enclosed block with a specific local timezone."""
    previous = os.environ.get('TZ')
    os.environ['TZ'] = name
    time.tzset()
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = previous
        time.tzset()

SAMPLE_SYSCALL = (
    'type=SYSCALL msg=audit(1734547436.320:852): arch=c000003e syscall=59 '
    'success=yes exit=0 a0=7fb27f458c70 a1=7fb27f458ce0 a2=56289c566760 '
    'a3=8 items=4 ppid=10424 pid=11969 auid=0 uid=0 gid=0 euid=0 suid=0 '
    'fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts2 ses=12 '
    'comm="disable-rootfs-" exe="/usr/bin/python3.11" subj=unconfined '
    'key="escalation" ARCH=x86_64 SYSCALL=execve AUID="root" UID="root" '
    'GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" '
    'SGID="root" FSGID="root"'
)

SAMPLE_CWD = 'type=CWD msg=audit(1734547436.320:852): cwd="/root"'

SAMPLE_PROCTITLE = (
    'type=PROCTITLE msg=audit(1734547436.320:852): '
    'proctitle=2F7573722F62696E2F707974686F6E33002F7573722F6C6F63616C2F'
    '6C6962657865632F64697361626C652D726F6F7466732D70726F74656374696F6E'
)


class TestParseMsgid:
    def test_basic_parsing(self):
        aid, time_str = parse_msgid(SAMPLE_MSGID)
        # Should be a valid UUID string
        assert len(aid) == 36
        assert aid.count('-') == 4
        # time is the UTC render of the auditd epoch timestamp
        assert time_str == SAMPLE_TIME_UTC

    def test_uuid_uniqueness(self):
        # Random bits should make each call produce a different UUID
        aid1, _ = parse_msgid(SAMPLE_MSGID)
        aid2, _ = parse_msgid(SAMPLE_MSGID)
        assert aid1 != aid2

    def test_time_is_utc_independent_of_local_timezone(self):
        # The 'time' field must be UTC regardless of the daemon's local timezone.
        for tz in ('Asia/Tokyo', 'America/Los_Angeles', 'UTC'):
            with local_timezone(tz):
                _aid, time_str = parse_msgid(SAMPLE_MSGID)
                assert time_str == SAMPLE_TIME_UTC, tz


class TestAuditEntryToJson:
    def test_basic_json_structure(self):
        result = audit_entry_to_json(
            SAMPLE_MSGID,
            AuditEvent.ESCALATION,
            [SAMPLE_SYSCALL, SAMPLE_CWD, SAMPLE_PROCTITLE],
        )
        assert result.startswith('@cee:')
        payload = json.loads(result[5:])
        tnaudit = payload['TNAUDIT']

        assert 'aid' in tnaudit
        assert tnaudit['vers'] == {'major': 0, 'minor': 1}
        assert tnaudit['svc'] == 'SYSTEM'
        assert 'time' in tnaudit
        assert 'event_data' in tnaudit

    def test_event_data_is_json_string(self):
        # Non single-record events (e.g. keyed SYSCALL) carry audit_msg_id_str
        # and the fixed key superset, with raw_lines collapsed to None.
        result = audit_entry_to_json(
            SAMPLE_MSGID,
            AuditEvent.ESCALATION,
            [SAMPLE_SYSCALL],
        )
        payload = json.loads(result[5:])
        # event_data should be a JSON string (double-encoded)
        event_data = json.loads(payload['TNAUDIT']['event_data'])
        assert isinstance(event_data, dict)
        assert 'audit_msg_id_str' in event_data
        assert event_data['raw_lines'] is None
        # The old handler's fixed superset is always present for these events.
        assert set(event_data) >= {'syscall', 'cwd', 'proctitle', 'paths'}

    def test_null_event_type(self):
        result = audit_entry_to_json(
            SAMPLE_MSGID,
            None,
            [SAMPLE_SYSCALL],
        )
        payload = json.loads(result[5:])
        assert 'event' in payload['TNAUDIT']

    def test_generic_event_retains_raw_lines(self):
        # A generic event with no SYSCALL record keeps the raw record text in
        # event_data['raw_lines'] (matching the old handler), rather than None.
        config_change = (
            'type=CONFIG_CHANGE msg=audit(1734547436.320:852): '
            'op=add_rule key="time-change" list=4 res=1'
        )
        result = audit_entry_to_json(SAMPLE_MSGID, None, [config_change])
        event_data = json.loads(json.loads(result[5:])['TNAUDIT']['event_data'])
        assert event_data['raw_lines'] == [config_change]
        assert event_data['syscall'] is None
        assert 'audit_msg_id_str' in event_data

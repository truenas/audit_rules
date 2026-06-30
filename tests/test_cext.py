# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

import pytest
import truenas_auparse


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

SAMPLE_PATH = (
    'type=PATH msg=audit(1734547436.320:852): item=1 '
    'name="/usr/local/libexec/disable-rootfs-protection" inode=46471 '
    'dev=00:23 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL '
    'cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 '
    'OUID="root" OGID="root"'
)

SAMPLE_PROCTITLE = (
    'type=PROCTITLE msg=audit(1734547436.320:852): '
    'proctitle=2F7573722F62696E2F707974686F6E33002F7573722F6C6F63616C2F'
    '6C6962657865632F64697361626C652D726F6F7466732D70726F74656374696F6E'
)

SAMPLE_CWD = 'type=CWD msg=audit(1734547436.320:852): cwd="/root"'

SAMPLE_LOGIN = (
    'type=LOGIN msg=audit(1735069956.674:1968): pid=38804 uid=0 '
    'subj=unconfined old-auid=4294967295 auid=0 tty=(none) '
    'old-ses=4294967295 ses=28 res=1 UID="root" OLD-AUID="unset" AUID="root"'
)

SAMPLE_EOE = 'type=EOE msg=audit(1734547436.320:852): '


class TestParseEvent:
    def test_syscall_record(self):
        result = truenas_auparse.parse_event(SAMPLE_SYSCALL)
        assert 'records' in result
        assert len(result['records']) == 1

        record = result['records'][0]
        assert record['type_name'] == 'SYSCALL'
        assert 'fields' in record

        fields = record['fields']
        assert 'key' in fields
        assert 'pid' in fields
        assert 'uid' in fields

    def test_path_record(self):
        result = truenas_auparse.parse_event(SAMPLE_PATH)
        assert len(result['records']) == 1

        record = result['records'][0]
        assert record['type_name'] == 'PATH'
        assert 'name' in record['fields']

    def test_multirecord_event(self):
        combined = '\n'.join([SAMPLE_SYSCALL, SAMPLE_PATH, SAMPLE_CWD, SAMPLE_PROCTITLE])
        result = truenas_auparse.parse_event(combined)
        assert len(result['records']) == 4

        type_names = [r['type_name'] for r in result['records']]
        assert 'SYSCALL' in type_names
        assert 'PATH' in type_names
        assert 'CWD' in type_names
        assert 'PROCTITLE' in type_names

    def test_login_record(self):
        result = truenas_auparse.parse_event(SAMPLE_LOGIN)
        assert len(result['records']) == 1
        assert result['records'][0]['type_name'] == 'LOGIN'

    def test_empty_input(self):
        result = truenas_auparse.parse_event('')
        assert result['records'] == []

    def test_invalid_type(self):
        with pytest.raises(TypeError):
            truenas_auparse.parse_event(123)


class TestGetRecordType:
    def test_syscall_type(self):
        assert truenas_auparse.get_record_type(SAMPLE_SYSCALL) == 'SYSCALL'

    def test_path_type(self):
        assert truenas_auparse.get_record_type(SAMPLE_PATH) == 'PATH'

    def test_login_type(self):
        assert truenas_auparse.get_record_type(SAMPLE_LOGIN) == 'LOGIN'

    def test_cwd_type(self):
        assert truenas_auparse.get_record_type(SAMPLE_CWD) == 'CWD'

    def test_proctitle_type(self):
        assert truenas_auparse.get_record_type(SAMPLE_PROCTITLE) == 'PROCTITLE'

    def test_eoe_type(self):
        assert truenas_auparse.get_record_type(SAMPLE_EOE) == 'EOE'

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            truenas_auparse.get_record_type('')


class TestAuparseContext:
    def test_create_context(self):
        ctx = truenas_auparse.AuparseContext(callback=lambda ev: None)
        assert ctx is not None

    def test_callback_not_callable(self):
        with pytest.raises(TypeError):
            truenas_auparse.AuparseContext(callback="not callable")

    def test_multipart_event(self):
        events = []
        ctx = truenas_auparse.AuparseContext(callback=events.append)

        ctx.feed(SAMPLE_SYSCALL)
        ctx.feed(SAMPLE_PATH)
        ctx.feed(SAMPLE_CWD)
        ctx.feed(SAMPLE_PROCTITLE)
        ctx.feed(SAMPLE_EOE)

        assert len(events) == 1
        event = events[0]
        assert 'records' in event
        type_names = [r['type_name'] for r in event['records']]
        assert 'SYSCALL' in type_names
        assert 'PATH' in type_names
        assert 'CWD' in type_names
        assert 'PROCTITLE' in type_names

    def test_eoe_triggers_callback(self):
        """Callback fires when event is flushed after EOE."""
        events = []
        ctx = truenas_auparse.AuparseContext(callback=events.append)

        ctx.feed(SAMPLE_SYSCALL)
        assert len(events) == 0

        ctx.feed(SAMPLE_EOE)
        ctx.flush()
        assert len(events) == 1

    def test_raw_lines_and_msgid(self):
        events = []
        ctx = truenas_auparse.AuparseContext(callback=events.append)

        ctx.feed(SAMPLE_SYSCALL)
        ctx.feed(SAMPLE_EOE)
        ctx.flush()

        assert len(events) == 1
        event = events[0]
        assert 'raw_lines' in event
        assert 'msgid' in event
        assert len(event['raw_lines']) > 0
        assert 'audit(' in event['msgid']

    def test_flush_incomplete(self):
        events = []
        ctx = truenas_auparse.AuparseContext(callback=events.append)

        ctx.feed(SAMPLE_SYSCALL)
        assert len(events) == 0

        ctx.flush()
        assert len(events) == 1

    def test_next_event_triggers_previous(self):
        """Feeding a subsequent event finalizes the previously buffered one.

        Whether libauparse also emits the new single-record event immediately
        (libauparse 3.x) or holds it until the next record/flush (4.x) is
        version-dependent, so assert only the version-independent invariant:
        the earlier SYSCALL event is delivered once a later event arrives, and
        flush() drains everything exactly once.
        """
        events = []
        ctx = truenas_auparse.AuparseContext(callback=events.append)

        # First event stays buffered until a later record or a flush arrives.
        ctx.feed(SAMPLE_SYSCALL)
        ctx.feed(SAMPLE_EOE)
        assert len(events) == 0

        # Feeding the next event (different msgid) finalizes the previous
        # SYSCALL event. libauparse may also emit the LOGIN event here, so
        # don't pin the exact count -- just require the SYSCALL was delivered.
        ctx.feed(SAMPLE_LOGIN)
        assert len(events) >= 1
        assert events[0]['msgid'] == 'audit(1734547436.320:852)'

        # Flushing drains any still-buffered event; both arrive exactly once.
        ctx.flush()
        assert [e['msgid'] for e in events] == [
            'audit(1734547436.320:852)',
            'audit(1735069956.674:1968)',
        ]

    def test_multiple_events(self):
        events = []
        ctx = truenas_auparse.AuparseContext(callback=events.append)

        # First event
        ctx.feed(SAMPLE_SYSCALL)
        ctx.feed(SAMPLE_EOE)
        # Second event
        ctx.feed(SAMPLE_LOGIN)
        ctx.feed('type=EOE msg=audit(1735069956.674:1968): ')
        ctx.flush()

        assert len(events) == 2

    def test_callback_exception_propagates(self):
        def bad_callback(ev):
            raise ValueError("test error")

        ctx = truenas_auparse.AuparseContext(callback=bad_callback)

        with pytest.raises(ValueError, match="test error"):
            ctx.feed(SAMPLE_SYSCALL)
            ctx.feed(SAMPLE_EOE)
            ctx.flush()

    def test_gc_does_not_crash(self):
        """AuparseContext is GC-tracked and does not corrupt the collector."""
        import gc

        truenas_auparse.AuparseContext(callback=lambda ev: None)
        gc.collect()

# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

from truenas_audit_parse.parsers import (
    classify_event,
    parse_multipart_event,
    process_syscall,
    process_path,
    process_login,
    process_service,
    process_pam,
    process_tty,
)
from truenas_audit_parse.event_types import AuditEvent


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

SAMPLE_LOGIN = (
    'type=LOGIN msg=audit(1735069956.674:1968): pid=38804 uid=0 '
    'subj=unconfined old-auid=4294967295 auid=0 tty=(none) '
    'old-ses=4294967295 ses=28 res=1 UID="root" OLD-AUID="unset" AUID="root"'
)

SAMPLE_SERVICE = (
    'type=SERVICE_START msg=audit(1736973663.599:429): pid=1 uid=0 '
    'auid=4294967295 ses=4294967295 subj=unconfined '
    "msg='unit=smbd comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" "
    "hostname=? addr=? terminal=? res=success' "
    'UID="root" AUID="unset"'
)


class TestClassifyEvent:
    def test_syscall_escalation(self):
        parsed = parse_multipart_event([SAMPLE_SYSCALL])
        assert classify_event(parsed) == AuditEvent.ESCALATION

    def test_login_event(self):
        parsed = parse_multipart_event([SAMPLE_LOGIN])
        assert classify_event(parsed) == AuditEvent.LOGIN

    def test_service_event(self):
        parsed = parse_multipart_event([SAMPLE_SERVICE])
        assert classify_event(parsed) == AuditEvent.SERVICE

    def test_empty_records(self):
        assert classify_event({'records': []}) == AuditEvent.GENERIC


class TestProcessSyscall:
    def test_success_conversion(self):
        fields = {'success': 'yes', 'pid': 'root', 'exit': '0'}
        raw = {'success': 'yes', 'pid': '1234', 'exit': '0'}
        result = process_syscall(fields, raw)
        assert result['success'] is True
        assert result['pid'] == 1234
        assert result['exit'] == 0

    def test_failure_conversion(self):
        fields = {'success': 'no', 'pid': 'root'}
        raw = {'success': 'no', 'pid': '5678'}
        result = process_syscall(fields, raw)
        assert result['success'] is False


class TestProcessPath:
    def test_int_conversion(self):
        fields = {'inode': '46471', 'ouid': 'root', 'ogid': 'root', 'name': '/tmp/test'}
        raw = {'inode': '46471', 'ouid': '0', 'ogid': '0', 'name': '/tmp/test'}
        result = process_path(fields, raw)
        assert result['inode'] == 46471
        assert result['ouid'] == 0
        assert result['name'] == '/tmp/test'


class TestProcessLogin:
    def test_int_fields(self):
        fields = {'ses': 'root', 'res': '1'}
        raw = {'ses': '28', 'res': '1'}
        result = process_login(fields, raw)
        assert result['ses'] == 28
        assert result['res'] == 1


class TestProcessService:
    def test_res_conversion(self):
        result = process_service({'res': 'success', 'unit': 'smbd'})
        assert result['res'] is True
        assert result['unit'] == 'smbd'


class TestProcessPam:
    def test_username_extraction(self):
        fields = {'pid': 'root', 'AUID': 'root', 'res': 'success'}
        raw = {'pid': '1234', 'AUID': '"root"', 'res': 'success'}
        result = process_pam(fields, raw)
        assert result['pid'] == 1234
        assert result['username'] == 'root'
        assert result['res'] is True

    def test_uid_skipped(self):
        result = process_pam({'UID': 'root', 'ID': 'root'})
        assert 'UID' not in result
        assert 'ID' not in result


class TestProcessTty:
    def test_int_fields(self):
        fields = {'pid': 'root', 'uid': 'root', 'ses': '16', 'major': '136', 'minor': '1'}
        raw = {'pid': '28250', 'uid': '0', 'ses': '16', 'major': '136', 'minor': '1'}
        result = process_tty(fields, raw)
        assert result['pid'] == 28250
        assert result['ses'] == 16

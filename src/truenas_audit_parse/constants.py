# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

import re

from .event_types import AuditMsgEventType

AUDITD_LINE_SEPARATOR = '\x1d'
AUDITD_NULL_VALUES = frozenset(['(null)', '(none)', '?', 'unset'])
JSON_NULL = 'null'
MULTIPART_EVENT_TYPES = frozenset([
    AuditMsgEventType.PROCTITLE, AuditMsgEventType.PATH,
    AuditMsgEventType.CWD, AuditMsgEventType.EXECVE,
    AuditMsgEventType.SYSCALL, AuditMsgEventType.CONFIG_CHANGE,
    AuditMsgEventType.EOE, AuditMsgEventType.BPF,
    AuditMsgEventType.LOGIN, AuditMsgEventType.TTY,
])
PAM_MSG_TYPES = frozenset([
    AuditMsgEventType.USER_START, AuditMsgEventType.USER_END,
    AuditMsgEventType.USER_ACCT, AuditMsgEventType.USER_AUTH,
    AuditMsgEventType.USER_LOGIN, AuditMsgEventType.USER_ERR,
    AuditMsgEventType.CRED_ACQ, AuditMsgEventType.CRED_REFR,
    AuditMsgEventType.CRED_DISP,
])
SERVICE_MSG_TYPES = frozenset([
    AuditMsgEventType.SERVICE_START, AuditMsgEventType.SERVICE_STOP,
])
PAM_SPLIT_PATTERN = re.compile(
    r'(?=\b(?:grantors|acct|exe|hostname|addr|terminal|res|UID|AUID|ID|GID)=)'
)

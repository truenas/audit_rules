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
# The record types the TrueNAS S3 daemon originates (see AUDIT.md in the
# truenas_s3 repository). USER_AUTH and USER_ACCT are shared with PAM;
# what marks a record as S3's is the op=s3d:<Operation> vocabulary.
S3_MSG_TYPES = frozenset([
    AuditMsgEventType.TRUSTED_APP, AuditMsgEventType.DAC_CHECK,
    AuditMsgEventType.USER_AUTH, AuditMsgEventType.USER_ACCT,
])
S3_OP_PREFIX = 's3d:'
PAM_SPLIT_PATTERN = re.compile(
    r'(?=\b(?:grantors|acct|exe|hostname|addr|terminal|res|UID|AUID|ID|GID)=)'
)

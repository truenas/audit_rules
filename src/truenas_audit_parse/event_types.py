# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

import enum


class AuditMsgEventType(enum.StrEnum):
    LOGIN = 'LOGIN'
    PROCTITLE = 'PROCTITLE'
    PATH = 'PATH'
    CWD = 'CWD'
    EXECVE = 'EXECVE'
    SYSCALL = 'SYSCALL'
    CONFIG_CHANGE = 'CONFIG_CHANGE'
    EOE = 'EOE'
    BPF = 'BPF'
    TTY = 'TTY'
    # PAM / credential record types
    USER_START = 'USER_START'
    USER_END = 'USER_END'
    USER_ACCT = 'USER_ACCT'
    USER_AUTH = 'USER_AUTH'
    USER_LOGIN = 'USER_LOGIN'
    USER_ERR = 'USER_ERR'
    CRED_ACQ = 'CRED_ACQ'
    CRED_REFR = 'CRED_REFR'
    CRED_DISP = 'CRED_DISP'
    # Service record types
    SERVICE_START = 'SERVICE_START'
    SERVICE_STOP = 'SERVICE_STOP'


class AuditEvent(enum.StrEnum):
    PRIVILEGED = 'privileged'
    ESCALATION = 'escalation'
    EXPORT = 'export'
    IDENTITY = 'identity'
    TIMECHANGE = 'time-change'
    MODULE = 'module-load'
    # Items below are not set as keys
    GENERIC = 'generic'
    LOGIN = 'login'
    SERVICE = 'service'
    CREDENTIAL = 'credential'
    TTY_RECORD = 'tty_record'

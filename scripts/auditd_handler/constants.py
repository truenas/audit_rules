import enum

from dataclasses import dataclass, field


AUDITD_LINE_SEPARATOR = '\x1d'


class AuditMsgOffset(enum.IntEnum):
    TYPE = 0
    MSGID = enum.auto()


AUDIT_BEGIN_OFFSET = AuditMsgOffset.MSGID + 1


class AuditPathOffset(enum.IntEnum):
    ITEM_NO = AUDIT_BEGIN_OFFSET
    NAME = enum.auto()
    INODE = enum.auto()
    DEV = enum.auto()
    MODE = enum.auto()
    OUID = enum.auto()
    OGID = enum.auto()
    RDEV = enum.auto()
    NAMETYPE = enum.auto()


class AuditProctitleOffset(enum.IntEnum):
    PROCTITLE = AUDIT_BEGIN_OFFSET


class AuditCwdOffset(enum.IntEnum):
    CWD = AUDIT_BEGIN_OFFSET


class AuditSyscallOffset(enum.IntEnum):
    ARCH = AUDIT_BEGIN_OFFSET
    SYSCALL = enum.auto()
    SUCCESS = enum.auto()
    EXIT = enum.auto()
    A0 = enum.auto()
    A1 = enum.auto()
    A2 = enum.auto()
    A3 = enum.auto()
    ITEMS = enum.auto()
    PPID = enum.auto()
    PID = enum.auto()
    AUID = enum.auto()
    UID = enum.auto()
    GID = enum.auto()
    EUID = enum.auto()
    SUID = enum.auto()
    FSUID = enum.auto()
    EGID = enum.auto()
    SGID = enum.auto()
    FSGID = enum.auto()
    TTY = enum.auto()
    SES = enum.auto()
    COMM = enum.auto()
    EXE = enum.auto()
    SUBJ = enum.auto()
    KEY = enum.auto()
    ARCH_STR = enum.auto()
    SYSCALL_STR = enum.auto()
    AUID_STR = enum.auto()
    UID_STR = enum.auto()
    GID_STR = enum.auto()
    EUID_STR = enum.auto()
    SUID_STR = enum.auto()
    FSUID_STR = enum.auto()
    EGID_STR = enum.auto()
    SGID_STR = enum.auto()
    FSGID_STR = enum.auto()


class AuditEvent(enum.StrEnum):
    PRIVILEGED = 'privileged'
    ESCALATION = 'escalation'
    EXPORT = 'export'
    IDENTITY = 'identity'
    TIMECHANGE = 'time-change'
    MODULE = 'module-load'
    GENERIC = 'generic'


@dataclass(slots=True)
class AUDITEntry:
    event_type: AuditEvent | None = None
    key_event: str | None = None
    raw_lines: list[str] = field(default_factory=list)


class AuditMsgEventType(enum.StrEnum):
    PROCTITLE = 'PROCTITLE'
    PATH = 'PATH'
    CWD = 'CWD'
    EXECVE = 'EXECVE'
    SYSCALL = 'SYSCALL'
    CONFIG_CHANGE = 'CONFIG_CHANGE'
    EOE = 'EOE'
    BPF = 'BPF'


MULTIPART_EVENT = frozenset([
    AuditMsgEventType.PROCTITLE,
    AuditMsgEventType.PATH,
    AuditMsgEventType.CWD,
    AuditMsgEventType.EXECVE,
    AuditMsgEventType.SYSCALL,
    AuditMsgEventType.CONFIG_CHANGE,
    AuditMsgEventType.EOE,
    AuditMsgEventType.BPF,
])

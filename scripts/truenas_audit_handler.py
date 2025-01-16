#!/usr/bin/python3

import argparse
import asyncio
import enum
import logging
import logging.handlers
import os
import signal
import stat

from codecs import decode
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict, deque
from json import dumps
from middlewared.logger import TNSyslogHandler
from queue import Queue
from random import getrandbits
from uuid import UUID


DESCRIPTION = (
    'Process audit messages in real time from the auditd dispatch unix domain '
    'socket and write them to the syslog-ng handler, and if required raise '
    'middlewared alerts for high priority items.'
)

DEFAULT_AUDISPD_SOCK = '/var/run/audispd_events'
DEFAULT_SYSLOG_SOCK = '/var/run/syslog-ng/auditd.sock'
DEFAULT_RECOVERY_FILE = '/var/run/middleware/.auditd_handler.recovery'
SYSLOG_IDENT = 'TNAUDIT_SYSTEM: '
AUDITD_LINE_SEPARATOR = '\x1d'
AUDITD_NULL_VALUES = frozenset(['(null)', '(none)', '?', 'unset'])
JSON_NULL = 'null'

# TODO: generate critical middleware alert if our backlog starts to hit
# critical levels
ALERT_QUEUE_DEPTH = 1024


class AuditMsgParser(enum.Enum):
    @property
    def idx(self) -> int:
        return self.value[0]

    @property
    def data_type(self) -> type:
        return self.value[1]

    def get_entry(self, data: list[str]) -> tuple:
        key, value = data[self.idx].split('=', 1)
        if self.data_type is str:
            # possibly strip leading and trailing quotes
            if value[0] == '"':
                value = value[1:]
            if value[-1] == '"':
                value = value[0:-1]

            # We may have literal string denoting a NULL value change back to
            # python None type, which will then be encoded as JSON NULL when
            # encoded for DB insertion.
            if value in AUDITD_NULL_VALUES:
                value = None

            return (key, value)

        elif self.data_type is bool:
            return (key, value == "yes")

        return (key, int(value))


class AuditMsgBase(AuditMsgParser):
    TYPE = (0, str)
    ID = (1, str)

    def get_entry(self, data: list[str]) -> tuple:
        if self is AuditMsgBase.TYPE:
            return super().get_entry(data)

        key, value = data[self.idx].split('=', 1)
        # ID has a trailing colon ":" that needs to be stripped
        return (key, value[0: -1])


def get_msg_type(data: list[str]) -> str:
    key, value = AuditMsgBase.TYPE.get_entry(data)
    return value


def get_msg_id(data: list[str]) -> str:
    key, value = AuditMsgBase.ID.get_entry(data)
    return value


class AuditMsgPath(AuditMsgParser):
    """
    Parser for path type entry

    Sample entry:
    "type=PATH msg=audit(1734547436.320:852): item=1 name=\"/usr/local/libexec/disable-rootfs-protection\" inode=46471 dev=00:23 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 OUID=\"root\" OGID=\"root\""  # noqa
    """
    NAME = (3, str)
    INODE = (4, int)
    DEV = (5, str)
    MODE = (6, str)
    OUID = (7, int)
    OGID = (8, int)
    RDEV = (9, str)


class AuditMsgProctitle(AuditMsgParser):
    """
    Parser for PROCTITLE type messages

    Sample entry:
    "type=PROCTITLE msg=audit(1734547436.320:852): proctitle=2F7573722F62696E2F707974686F6E33002F7573722F6C6F63616C2F6C6962657865632F64697361626C652D726F6F7466732D70726F74656374696F6E"  # noqa
    """
    PROCTITLE = (2, str)

    def get_entry(self, data: list[str]) -> tuple:
        key, value = super().get_entry(data)

        # Although userspace library guidelines state to hex-encode this value
        # some libaudit consumers break (notably pam_tty_audit) break this expectation.
        # If we fail to decode simply put original string in message.
        try:
            proc = decode(value, 'hex').decode().replace('\x00', ' ')
        except Exception:
            proc = value

        return (key, proc)


class AuditMsgCwd(AuditMsgParser):
    """
    Parser for CWD type messages

    Sample entry:
    "type=CWD msg=audit(1734547436.320:852): cwd=\"/root\""
    """
    CWD = (2, str)


class AuditMsgSyscall(AuditMsgParser):
    """
    Parser for SYSCALL type messages

    Sample entry:
    "type=SYSCALL msg=audit(1734547436.320:852): arch=c000003e syscall=59 success=yes exit=0 a0=7fb27f458c70 a1=7fb27f458ce0 a2=56289c566760 a3=8 items=4 ppid=10424 pid=11969 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts2 ses=12 comm=\"disable-rootfs-\" exe=\"/usr/bin/python3.11\" subj=unconfined key=\"escalation\" ARCH=x86_64 SYSCALL=execve AUID=\"root\" UID=\"root\" GID=\"root\" EUID=\"root\" SUID=\"root\" FSUID=\"root\" EGID=\"root\" SGID=\"root\" FSGID=\"root\"  # noqa
    """
    SUCCESS = (4, bool)
    EXIT = (5, int)
    PPID = (11, int)
    PID = (12, int)
    AUID = (13, int)
    UID = (14, int)
    GID = (15, int)
    EUID = (16, int)
    SUID = (17, int)
    FSUID = (18, int)
    EGID = (19, int)
    SGID = (20, int)
    FSGID = (21, int)
    TTY = (22, str)
    SES = (23, int)
    KEY = (27, str)
    SYSCALL_STR = (29, str)
    AUID_STR = (30, str)
    UID_STR = (31, str)
    GID_STR = (32, str)


class AuditMsgSyscallNoRval(AuditMsgParser):
    """
    Some syscall entries do not have a proper exit code

    Sample entry:
    type=SYSCALL msg=audit(1735072331.659:2032): arch=c000003e syscall=231 a0=0 a1=e7 a2=3c a3=7ffd914e4b20 items=0 ppid=42401 pid=42411 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=33 comm="zsh" exe="/usr/bin/zsh" subj=unconfined key=(null) ARCH=x86_64 SYSCALL=exit_group AUID="root" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"  # noqa
    """
    PPID = (9, int)
    PID = (10, int)
    AUID = (11, int)
    UID = (12, int)
    GID = (13, int)
    EUID = (14, int)
    SUID = (15, int)
    FSUID = (16, int)
    EGID = (17, int)
    SGID = (18, int)
    FSGID = (19, int)
    TTY = (20, str)
    SES = (21, int)
    EXE = (23, str)
    KEY = (25, str)
    SYSCALL_STR = (27, str)
    AUID_STR = (28, str)
    UID_STR = (29, str)
    GID_STR = (30, str)


class AuditMsgLogin(AuditMsgParser):
    """
    Parser for LOGIN type messages

    Sample entry:
    type=LOGIN msg=audit(1735069956.674:1968): pid=38804 uid=0 subj=unconfined old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=28 res=1 UID="root" OLD-AUID="unset" AUID="root"  # noqa
    """
    OLD_AUID = (5, int)
    NEW_AUID = (6, int)
    TTY = (7, str)
    OLD_SES = (8, int)
    NEW_SES = (9, int)
    RES = (10, int)


class AuditMsgService(AuditMsgParser):
    """
    Parser for SERVICE_START and SERVICE_STOP messages

    Sample entry:
    "type=SERVICE_START msg=audit(1736973663.599:429): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='unit=smbd comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" hostname=? addr=? terminal=? res=success' UID=\"root\" AUID=\"unset\""  # noqa
    """
    SUBJ = (6, str)
    UNIT = (7, str)
    COMM = (8, str)
    EXE = (9, str)
    RES = (13, str)

    def get_entry(self, data: list[str]) -> tuple:
        key, value = super().get_entry(data)
        match self:
            case AuditMsgService.UNIT:
                value = value.split('=', 1)[1]
                key = 'unit'
            case AuditMsgService.RES:
                value = 'success' in value
            case _:
                pass

        return (key, value)


class AuditMsgPamBase(AuditMsgParser):
    PID = (2, int)
    FUNCTION = (7, str)

    def get_entry(self, data: list[str]) -> tuple:
        key, value = super().get_entry(data)
        if self is AuditMsgPamBase.FUNCTION:
            value = value.split('=', 1)[1]
            key = 'function'

        return (key, value)


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


class AuditEvent(enum.StrEnum):
    PRIVILEGED = 'privileged'
    ESCALATION = 'escalation'
    EXPORT = 'export'
    IDENTITY = 'identity'
    TIMECHANGE = 'time-change'
    MODULE = 'module-load'
    GENERIC = 'generic'
    LOGIN = 'login'
    SERVICE = 'service'
    CREDENTIAL = 'credential'


def get_audit_event(parts: list[str]) -> AuditEvent | None:
    # only syscall events will have the key loaded
    if get_msg_type(parts) != 'SYSCALL':
        return None

    # Some syscalls may not have a return value in the audit entry
    # The simplest way to determine which type of record we have is to
    # read the beginning the string at the SUCCESS offset.
    if not parts[AuditMsgSyscall.SUCCESS.idx].startswith('success'):
        msg_obj = AuditMsgSyscallNoRval
    else:
        msg_obj = AuditMsgSyscall

    key, value = msg_obj.KEY.get_entry(parts)
    if value is None:
        return AuditEvent.GENERIC

    return AuditEvent(value)


@dataclass(slots=True)
class AUDITEntry:
    event_type: AuditEvent | None = None
    key_event: str | None = None
    raw_lines: list[str] = field(default_factory=list)


MULTIPART_EVENT = frozenset([
    AuditMsgEventType.PROCTITLE,
    AuditMsgEventType.PATH,
    AuditMsgEventType.CWD,
    AuditMsgEventType.EXECVE,
    AuditMsgEventType.SYSCALL,
    AuditMsgEventType.CONFIG_CHANGE,
    AuditMsgEventType.EOE,
    AuditMsgEventType.BPF,
    AuditMsgEventType.LOGIN,
    AuditMsgEventType.TTY,
])


def __parse_cwd(msg_parts: list, event_data: dict) -> None:
    key, cwd = AuditMsgCwd.CWD.get_entry(msg_parts)
    event_data['cwd'] = cwd


def __parse_path(msg_parts: list, paths: list) -> None:
    path_entry = {}

    # deliberately leave off the item number from the line since it
    # can be inferred from array index.
    for item in AuditMsgPath:
        key, value = item.get_entry(msg_parts)
        path_entry[key] = value

    paths.append(path_entry)


def __parse_proctitle(msg_parts: list, event_data: dict) -> None:
    key, proctitle = AuditMsgProctitle.PROCTITLE.get_entry(msg_parts)
    event_data['proctitle'] = proctitle


def __parse_syscall(msg_parts: list, event_data: dict) -> None:
    if event_data.get('syscall') is not None:
        return

    event_data['syscall'] = {}

    # Some syscalls may not have a return value in the audit entry
    # The simplest way to determine which type of record we have is to
    # read the beginning the string at the SUCCESS offset.
    if not msg_parts[AuditMsgSyscall.SUCCESS.idx].startswith('success'):
        msg_obj = AuditMsgSyscallNoRval
    else:
        msg_obj = AuditMsgSyscall

    for item in msg_obj:
        key, value = item.get_entry(msg_parts)
        event_data['syscall'][key] = value


def __parse_login(msg_parts: list) -> dict:
    event_data = {'event_type': AuditEvent.LOGIN.upper()}

    for item in AuditMsgLogin:
        key, value = item.get_entry(msg_parts)
        event_data[key] = value

    return event_data


def __parse_service(msg_type: str, msg_parts: list) -> dict:
    event_data = {'event_type': AuditEvent.SERVICE.upper(), 'service_action': msg_type}

    for item in AuditMsgService:
        key, value = item.get_entry(msg_parts)
        event_data[key] = value

    return event_data


def __parse_pam(msg_type: str, msg_parts: list) -> dict:
    event_data = {'event_type': AuditEvent.CREDENTIAL.upper(), 'auth_action': msg_type}

    for item in AuditMsgPamBase:
        key, value = item.get_entry(msg_parts)
        event_data[key] = value

    # Everything after pam function is variable
    for item in msg_parts[AuditMsgPamBase.FUNCTION.idx + 1:]:
        key, value = item.split('=', 1)

        if value[0] == '"':
            value = value[1:]
        if value[-1] == '"':
            value = value[0:-1]

        if value.isdigit():
            value = int(value)
        elif value in AUDITD_NULL_VALUES:
            value = None

        match key:
            case 'res':
                value = value.startswith('success')
            case 'AUID':
                key = 'username'
            case 'UID' | 'ID':
                # We're only concerned about logging the audit uid
                continue
            case _:
                pass

        event_data[key] = value

    return event_data


def __parse_raw_msg(msg: str, event_data: dict):
    # We can include inferred items in our entry
    parts = msg.split()
    msg_type = get_msg_type(parts)

    match msg_type:
        case 'PATH':
            return __parse_path(parts, event_data['paths'])
        case 'PROCTITLE':
            return __parse_proctitle(parts, event_data)
        case 'CWD':
            return __parse_cwd(parts, event_data)
        case 'SYSCALL':
            return __parse_syscall(parts, event_data)
        # Below this point are single-part events that return customized
        # Event data
        case 'LOGIN':
            return __parse_login(parts)
        case 'SERVICE_START' | 'SERVICE_STOP':
            return __parse_service(msg_type, parts)
        case 'USER_START' | 'USER_END' | 'USER_ACCT' | 'USER_AUTH' | 'USER_LOGIN' | 'USER_ERR':
            return __parse_pam(msg_type, parts)
        case 'CRED_ACQ' | 'CRED_REFR' | 'CRED_DISP':
            return __parse_pam(msg_type, parts)
        case _:
            pass


def __generate_event_data(
    entry: AUDITEntry,
    data_out: dict
) -> None:

    data_out['event'] = data_out['event'].upper()
    raw_lines = entry.raw_lines

    if entry.key_event:
        key, user = AuditMsgSyscall.UID_STR.get_entry(entry.key_event)
        data_out['user'] = user

        key, success = AuditMsgSyscall.SUCCESS.get_entry(entry.key_event)
        data_out['success'] = success
        data_out['event_data']['raw_lines'] = None

    for item in raw_lines:
        if (new_event_data := __parse_raw_msg(item, data_out['event_data'])) is not None:
            # If event is GENERIC then the entry is defaulted and we can
            # overwrite safely without losing info
            if data_out['event'] == AuditEvent.GENERIC.upper():
                data_out['event_data'] = new_event_data
                data_out['event'] = data_out['event_data'].pop('event_type')

            # This in principle shouldn't happen but to be on safe side we merge
            # event data
            else:
                new_event_data.pop('event_type')
                data_out['event_data'] | new_event_data

            if (username := new_event_data.get('username') or new_event_data.get('acct')) is not None:
                if not data_out['user']:
                    data_out['user'] = username

            if (addr := new_event_data.get('addr')) and data_out['addr'] == '127.0.0.1':
                data_out['addr'] = addr

            if (res := new_event_data.get('res')) is not None:
                if isinstance(res, bool):
                    data_out['success'] = res


def __parse_msgid(msgid: str, entry_data: dict):
    """
    msgid is string such as audit(1734419821.939:3615). The part before the `:`
    character is a timestamp and the part after it is the audit event id.
    We need to convert this string into a UUID for the audit event.

    Unfortunately the audit event id is only an unsigned int, and so it's not
    actually universally unique and potentialy not unique over time.

    We convert this into a UUID by moving the timestamp to upper 64 bits of a
    128 bit integer, using the audit event id as the bottom 32 bits, and then
    placing random 32 bits in the middle of it.
    """
    msgid = msgid.split('(')[1].strip(')')
    timestamp, eventid = msgid.split(':')
    ts_datetime = datetime.fromtimestamp(float(timestamp))

    upper_64 = int(timestamp.replace('.', '')) << 64
    lower_32 = int(eventid)
    mid_32 = getrandbits(32) << 32

    entry_data['time'] = ts_datetime.strftime('%Y-%m-%d %H:%M:%S.%f')
    entry_data['aid'] = str(UUID(int=upper_64 + lower_32 + mid_32))


def audit_entry_to_json(msgid: str, entry: AUDITEntry) -> str:
    to_write = {'TNAUDIT': {
        'aid': None,
        'vers': {'major': 0, 'minor': 1},
        'addr': '127.0.0.1',
        'user': None,
        'sess': None,
        'time': None,
        'svc': 'SYSTEM',
        'svc_data': JSON_NULL,  # per our NEP null is OK here
        'event': entry.event_type or AuditEvent.GENERIC,
        'event_data': {
            'audit_msg_id_str': msgid,
            'proctitle': None,
            'syscall': None,
            'cwd': None,
            'paths': [],
            'raw_lines': entry.raw_lines
        },
        'success': True
    }}

    __parse_msgid(msgid, to_write['TNAUDIT'])
    __generate_event_data(entry, to_write['TNAUDIT'])

    to_write['TNAUDIT']['event_data'] = dumps(to_write['TNAUDIT']['event_data'])

    return '@cee:' + dumps(to_write)


class AuditdHandler:
    def __init__(
        self,
        audis_sock: str,
        syslog_sock: str,
        recovery_file: str,
        loop: asyncio.AbstractEventLoop
    ):
        self.exit = False
        self.loop = loop
        self.logger = None
        self.syslog_handler = None
        self.audis_path = audis_sock
        self.syslog_path = syslog_sock
        self.recovery_file = recovery_file
        self.syslog_queue_listener = None
        self.audis_reader = None
        self.audis_writer = None
        self.partial_records = defaultdict(AUDITEntry)
        self.pending_queue = deque()
        self.__setup_logger()
        self.__read_recovery_file()

    def __setup_logger(self) -> logging.Logger:
        # Set up logging queue to make sending messages to syslog nonblocking
        logq = Queue()
        queue_handler = logging.handlers.QueueHandler(logq)
        queue_handler.setLevel(logging.DEBUG)
        audit_handler = TNSyslogHandler(self.syslog_path, self.pending_queue)
        audit_handler.setLevel(logging.DEBUG)
        audit_handler.ident = SYSLOG_IDENT

        # Syslog messages are sent in separate thread
        queue_listener = logging.handlers.QueueListener(logq, audit_handler)
        queue_listener.start()
        logger = logging.getLogger('AuditLogger')
        logger.addHandler(queue_handler)
        self.logger = logger
        self.syslog_hander = audit_handler
        self.syslog_queue_listener = queue_listener

    def __write_recovery_file(self):
        with open(self.recovery_file, 'w') as f:
            while self.pending_queue:
                record = self.pending_queue.popleft()
                f.write(f'{record.msg}\n')

            f.flush()

    def __read_recovery_file(self):
        # read our recovery file into the pending queue and then remove it.
        if not os.path.exists(self.recovery_file):
            return

        with open(self.recovery_file, 'r') as f:
            for line in f:
                # immediately emit events in recovery file
                self.logger.critical(line)

        os.unlink(self.recovery_file)

    def terminate(self):
        # By this point our logger has shut down, but we may have a queue.
        self.__write_recovery_file()

        # Setting our reader / writer to None breaks out of loop
        self.audis_reader = None
        self.audis_writer = None

    async def __setup_reader(self) -> None:
        r, w = await asyncio.open_unix_connection(path=self.audis_path)
        self.audis_reader = r
        self.audis_writer = w

    async def send_completed(self, msgid: str, data: AUDITEntry) -> None:
        json_data = audit_entry_to_json(msgid, data)
        self.logger.critical(json_data)

    async def parse_audit_line(self, line: bytes):
        # decode and strip off trailing newline character
        decoded = line.decode()[0:-1]
        if not decoded:
            return

        decoded = decoded.replace(AUDITD_LINE_SEPARATOR, ' ')

        parts = decoded.split()
        msgid = get_msg_id(parts)
        msgtype = get_msg_type(parts)

        if msgtype not in MULTIPART_EVENT:
            return (msgid, AUDITEntry(raw_lines=[decoded]))

        # Keep adding to raw_lines until we get an End of Event (EOE) message.
        entry = self.partial_records[msgid]
        entry.raw_lines.append(decoded)

        # prioritize line with the identifier key
        if (audit_event := get_audit_event(parts)) is not None:
            entry.event_type = audit_event
            entry.key_event = parts

        if msgtype != AuditMsgEventType.EOE:
            # Incomplete message. We store in `partial_records` dictionary
            # until it is completed.
            return None

        return (msgid, self.partial_records.pop(msgid))

    async def handle_auditd_msg(self):
        # Auditd messages are newline-terminated
        data = await self.audis_reader.readline()
        if (completed := await self.parse_audit_line(data)) is not None:
            await self.send_completed(*completed)

    def __setup_signal_handlers(self):
        self.loop.add_signal_handler(signal.SIGTERM, self.terminate)
        self.loop.add_signal_handler(signal.SIGINT, self.terminate)

    async def run(self):
        await self.__setup_reader()
        self.__setup_signal_handlers()

        while self.audis_reader:
            await self.handle_auditd_msg()


def __process_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        '-a', '--audit-socket',
        help='Path to audispd-af_unix socket.',
        default=DEFAULT_AUDISPD_SOCK
    )
    parser.add_argument(
        '-s', '--syslog-socket',
        help='Path to syslog unix socket.',
        default=DEFAULT_SYSLOG_SOCK
    )
    parser.add_argument(
        '-', '--recovery-file',
        help='Path to recovery file.',
        default=DEFAULT_RECOVERY_FILE
    )
    return parser.parse_args()


def __validate_socket_path(path: str):
    if not stat.S_ISSOCK(os.stat(path).st_mode):
        raise RuntimeError(f'{path}: not a socket.')


def __validate_args(args: argparse.Namespace):
    __validate_socket_path(args.audit_socket)


def main():
    loop = asyncio.get_event_loop()
    args = __process_args()
    __validate_args(args)
    handler = AuditdHandler(
        args.audit_socket,
        args.syslog_socket,
        args.recovery_file,
        loop
    )
    loop.run_until_complete(handler.run())


if __name__ == '__main__':
    main()

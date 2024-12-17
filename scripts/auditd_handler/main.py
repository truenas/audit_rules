import argparse
import asyncio
import logging
import os
import stat

from collections import defaultdict, deque
from syslog import openlog, syslog
from .constants import AUDITEntry, AUDITD_LINE_SEPARATOR, AuditMsgEventType
from .parser import (
    get_msg_id,
    get_msg_type,
    get_audit_event,
    entry_type_is_multipart,
    audit_entry_to_json,
)

DESCRIPTION = (
    'Process audit messages in real time from the auditd dispatch unix domain '
    'socket and write them to the syslog-ng handler, and if required raise '
    'middlewared alerts for high priority items.'
)

DEFAULT_AUDISPD_SOCK = '/var/run/audispd_events'
SYSLOG_IDENT = 'TNAUDIT_SYSTEM'


class AuditdHandler:
    def __init__(self, audis_sock: str, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.audis_path = audis_sock
        self.audis_reader = None
        self.audis_writer = None
        self.partial_records = defaultdict(AUDITEntry)
        self.alerts_queue = deque()  # Queue for alerts to send to middlewared process

    async def __setup_reader(self) -> None:
        r, w = await asyncio.open_unix_connection(path=self.audis_path)
        self.audis_reader = r
        self.audis_writer = w

    async def __send_entry_impl(self, json_data: str) -> None:
        await self.loop.run_in_executor(None, syslog, json_data)

    async def send_completed(self, msgid: str, data: AUDITEntry) -> None:
        json_data = audit_entry_to_json(msgid, data)
        return await self.__send_entry_impl(json_data)

    async def parse_audit_line(self, line: bytes):
        # decode and strip off trailing newline character
        decoded = line.decode()[0:-1]
        if not decoded:
            return

        decoded = decoded.replace(AUDITD_LINE_SEPARATOR, ' ')

        parts = decoded.split()
        msgid = get_msg_id(parts)
        msgtype = get_msg_type(parts)

        if not entry_type_is_multipart(msgtype):
            return None

        entry = self.partial_records[msgid]
        entry.raw_lines.append(decoded)

        # prioritize line with the identifier key
        if (audit_event := get_audit_event(parts)) is not None:
            entry.event_type = audit_event
            entry.key_event = parts

        if msgtype != AuditMsgEventType.EOE:
            # Incomplete message. Cache it up.
            return None

        return (msgid, self.partial_records.pop(msgid))

    async def handle_auditd_msg(self):
        data = await self.audis_reader.readline()
        if (completed := await self.parse_audit_line(data)) is not None:
            await self.send_completed(*completed)

    async def run(self):
        await self.__setup_reader()
        await self.loop.run_in_executor(None, openlog, SYSLOG_IDENT)

        while True:
            await self.handle_auditd_msg()


def __process_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        '-a', '--audit-socket',
        help='Path to audispd-af_unix socket.',
        default=DEFAULT_AUDISPD_SOCK
    )
    return parser.parse_args()


def __validate_socket_path(path: str):
    if not stat.S_ISSOCK(os.stat(path).st_mode):
        raise RuntimeError(f'{path}: not a socket.')


def __validate_args(args: argparse.Namespace):
    __validate_socket_path(args.audit_socket)


async def main():
    loop = asyncio.get_running_loop()
    args = __process_args()
    await loop.run_in_executor(None, __validate_args, args)
    handler = AuditdHandler(args.audit_socket, loop)
    await handler.run()


if __name__ == 'main':
     loop = asyncio.get_event_loop()
     loop.run_until_complete(main())

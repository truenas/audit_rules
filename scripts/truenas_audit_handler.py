#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

import argparse
import asyncio
import logging
import logging.handlers
import os
import signal
import stat
import time

from truenas_api_client import Client

from collections import deque
from middlewared.logger import (
    TNSyslogHandler, TNLog, DEFAULT_LOGFORMAT, AUDIT_HANDLER_LOGFILE, QFORMATTER
)
import socket
from queue import Queue

import truenas_auparse
from truenas_audit_parse import (
    audit_entry_to_json, classify_event,
)
from truenas_audit_parse.constants import AUDITD_LINE_SEPARATOR
from truenas_audit_parse.event_types import AuditMsgEventType


DESCRIPTION = (
    'Process audit messages in real time from the auditd dispatch unix domain '
    'socket and write them to the syslog-ng handler, and if required raise '
    'middlewared alerts for high priority items.'
)

DEFAULT_AUDISPD_SOCK = '/var/run/audispd_events'
DEFAULT_SYSLOG_SOCK = '/var/run/syslog-ng/auditd.sock'
DEFAULT_RECOVERY_FILE = '/var/run/middleware/.auditd_handler.recovery'

# Module-level diagnostic logger (configured in main())
diag_logger = None
DEFAULT_DIAG_SYSLOG_SOCK = '/dev/log'
SYSLOG_IDENT = 'TNAUDIT_SYSTEM: '

ENTERPRISE_CHECK_TIMEOUT = 60    # seconds to retry initial middlewared connection
ENTERPRISE_CHECK_INTERVAL = 2    # seconds between retries during initial check
ENTERPRISE_RECHECK_INTERVAL = 300  # seconds between polls in the CE no-op loop

# TODO: generate critical middleware alert if our backlog starts to hit
# critical levels
ALERT_QUEUE_DEPTH = 1024

# Diagnostic logging configuration for the audit handler daemon
# This creates a separate log file for operational/diagnostic logging
# The logfile path is defined in middlewared/logger.py and automatically
# configured in syslog-ng via Mako templates
AUDIT_HANDLER_LOG = TNLog(
    name='audit_handler',
    logfile=AUDIT_HANDLER_LOGFILE,
    logformat=DEFAULT_LOGFORMAT,
    pending_maxlen=1024
)

F = open('/var/log/audit/audump.txt', 'wb')

def write_msg(msg):
    F.write(msg + b'\n')
    F.flush()


class DevLogSyslogHandler(logging.handlers.SysLogHandler):
    """
    Custom SysLogHandler for /dev/log that uses SOCK_DGRAM.

    TNSyslogHandler uses SOCK_STREAM which /dev/log doesn't accept.
    This handler uses SOCK_DGRAM (datagram) which is the standard for /dev/log.
    Includes pending queue support like TNSyslogHandler.
    """
    def __init__(self, address: str, pending_queue: deque | None = None):
        self.pending_queue = pending_queue
        self.fallback_handler = None
        # Use SOCK_DGRAM for /dev/log compatibility
        super().__init__(address, socktype=socket.SOCK_DGRAM)

    def drain_pending_queue(self) -> bool:
        """Drain any queued log records. Returns True if fully drained."""
        while self.pending_queue:
            record = self.pending_queue.popleft()
            try:
                super().emit(record)
            except Exception:
                self.pending_queue.appendleft(record)
                return False
        return True

    def fallback(self, record: logging.LogRecord) -> None:
        """Write to fallback handler if syslog unavailable."""
        if self.fallback_handler:
            try:
                self.fallback_handler.emit(record)
            except Exception:
                pass

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a record, using pending queue and fallback on failure."""
        if not self.drain_pending_queue():
            self.pending_queue.append(record)
            self.fallback(record)
            return

        try:
            super().emit(record)
        except Exception:
            self.pending_queue.append(record)
            self.fallback(record)

    def handleError(self, record: logging.LogRecord) -> None:
        """Override error handler to re-raise when using pending queue."""
        if self.pending_queue is None:
            return super().handleError(record)
        raise

    def set_fallback_handler(self, fallback: logging.Handler) -> None:
        """Set a fallback handler for when syslog is unavailable."""
        if not isinstance(fallback, logging.Handler):
            raise TypeError(f'{fallback}: not a logging.Handler')
        self.fallback_handler = fallback

    def close(self) -> None:
        """Close the handler and any fallback handler."""
        super().close()
        if self.fallback_handler:
            self.fallback_handler.close()
            self.fallback_handler = None


def setup_syslog_handler_custom_socket(
    tnlog: TNLog,
    fallback: logging.Handler | None,
    socket_path: str
) -> logging.Logger:
    """
    Create a syslog handler using middleware infrastructure with a custom socket.

    This function replicates the middleware's setup_syslog_handler behavior
    but allows specifying a custom socket path (e.g., /dev/log for journald).
    Uses DevLogSyslogHandler with SOCK_DGRAM for /dev/log compatibility.

    Args:
        tnlog: TNLog configuration object from middleware
        fallback: Optional fallback handler for when syslog is unavailable
        socket_path: Path to syslog socket (e.g., /dev/log, /var/run/syslog-ng/*.sock)

    Returns:
        Configured logger instance
    """
    # Use QueueHandler to avoid blocking IO in asyncio main loop
    log_queue = Queue()
    queue_handler = logging.handlers.QueueHandler(log_queue)

    # Format python exceptions into structured data
    queue_handler.setFormatter(QFORMATTER)

    # Create syslog handler with SOCK_DGRAM for /dev/log compatibility
    syslog_handler = DevLogSyslogHandler(
        address=socket_path,
        pending_queue=deque(maxlen=tnlog.pending_maxlen)
    )
    syslog_handler.setLevel(logging.DEBUG)

    # Apply log format if specified
    if tnlog.logformat:
        syslog_handler.setFormatter(
            logging.Formatter(tnlog.logformat, '%Y/%m/%d %H:%M:%S')
        )

    # Set ident for syslog-ng filtering
    syslog_handler.ident = tnlog.get_ident()

    # Set fallback handler if provided
    if fallback:
        syslog_handler.set_fallback_handler(fallback)

    # Start queue listener in separate thread
    queue_listener = logging.handlers.QueueListener(log_queue, syslog_handler)
    queue_listener.start()

    # Configure and return logger
    logger = logging.getLogger(tnlog.name)
    logger.addHandler(queue_handler)
    if tnlog.name is not None:
        logging.getLogger(tnlog.name).propagate = False

    return logger


def setup_diagnostic_logger() -> logging.Logger:
    """
    Configure the module-level diagnostic logger for operational/daemon logging.

    Sets up logging to /dev/log (journald) with fallback to a rotating file.
    This should be called once from main() before creating AuditHandler instance.

    Returns:
        Configured logger instance
    """
    global diag_logger

    # Set up fallback handler for when /dev/log is unavailable
    fallback_handler = logging.handlers.RotatingFileHandler(
        '/var/log/audit/audit_handler_fallback.log',
        'a',
        10485760,  # 10MB
        5,         # 5 backups
        'utf-8'
    )
    fallback_handler.setLevel(logging.DEBUG)
    fallback_handler.setFormatter(logging.Formatter(DEFAULT_LOGFORMAT, '%Y/%m/%d %H:%M:%S'))

    # Log diagnostic messages to /dev/log (journald) to avoid middleware.sock
    # Messages flow: /dev/log -> journald -> syslog-ng (s_src) -> audit_handler.log
    diag_logger = setup_syslog_handler_custom_socket(
        AUDIT_HANDLER_LOG,
        fallback_handler,
        DEFAULT_DIAG_SYSLOG_SOCK  # /dev/log
    )
    diag_logger.setLevel(logging.DEBUG)
    diag_logger.info("Audit handler diagnostic logging initialized")

    return diag_logger


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
        self.logger = None  # Audit event logger (writes JSON audit events)
        self.syslog_handler = None
        self.audis_path = audis_sock
        self.syslog_path = syslog_sock
        self.recovery_file = recovery_file
        self.syslog_queue_listener = None
        self.diag_queue_listener = None
        self.audis_reader = None
        self.audis_writer = None
        self.pending_queue = deque()
        self.__setup_logger()
        self.auparse_ctx = truenas_auparse.AuparseContext(callback=self._on_event_ready)
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
        queue_len = len(self.pending_queue)
        if queue_len == 0:
            diag_logger.debug("No pending messages to write to recovery file")
            return

        diag_logger.warning("Writing %r pending messages to recovery file", self.recovery_file)
        with open(self.recovery_file, 'w') as f:
            while self.pending_queue:
                record = self.pending_queue.popleft()
                f.write(f'{record.msg}\n')

            f.flush()
        diag_logger.info("Recovery file written successfully with %d messages", queue_len)

    def __read_recovery_file(self):
        # read our recovery file into the pending queue and then remove it.
        if not os.path.exists(self.recovery_file):
            diag_logger.debug("No recovery file found at %r", self.recovery_file)
            return

        diag_logger.info("Recovery file found at %r, replaying messages", self.recovery_file)
        msg_count = 0
        with open(self.recovery_file, 'r') as f:
            for line in f:
                # immediately emit events in recovery file
                self.logger.critical(line)
                msg_count += 1

        os.unlink(self.recovery_file)
        diag_logger.info("Replayed %d messages from recovery file", msg_count)

    def terminate(self):
        diag_logger.info("Received termination signal, shutting down audit handler")
        # By this point our logger has shut down, but we may have a queue.
        self.__write_recovery_file()

        # Setting our reader / writer to None breaks out of loop
        self.audis_reader = None
        self.audis_writer = None
        diag_logger.info("Audit handler terminated")

    async def __setup_reader(self) -> None:
        diag_logger.info("Connecting to audispd socket at %r", self.audis_path)
        try:
            r, w = await asyncio.open_unix_connection(path=self.audis_path)
            self.audis_reader = r
            self.audis_writer = w
            diag_logger.info("Successfully connected to audispd socket")
        except Exception:
            diag_logger.exception("Failed to connect to audispd socket.")
            raise

    def _on_event_ready(self, event: dict):
        """Called synchronously from C callback when a complete event is assembled."""
        msgid = event.get('msgid', '')
        raw_lines = event.get('raw_lines', [])
        event_type = classify_event(event)

        key_event_parts = None
        for record in event.get('records', []):
            if record.get('type_name') == AuditMsgEventType.SYSCALL:
                key = record.get('fields', {}).get('key')
                if key and key not in ('(null)', '(none)', '?', 'unset'):
                    # Find matching raw line for key_event_parts
                    for raw_line in raw_lines:
                        if raw_line.startswith(f'type={AuditMsgEventType.SYSCALL} '):
                            key_event_parts = raw_line.split()
                            break
                break

        json_data = audit_entry_to_json(
            msgid, event_type, raw_lines, key_event_parts, parsed=event
        )
        self.logger.critical(json_data)

    async def parse_audit_line(self, line: bytes):
        try:
            decoded = line.decode()[0:-1]
        except Exception:
            diag_logger.exception("Failed to decode audit line.")
            return

        if not decoded:
            return

        decoded = decoded.replace(AUDITD_LINE_SEPARATOR, ' ')

        try:
            self.auparse_ctx.feed(decoded)
        except Exception:
            diag_logger.exception("Failed to feed line to auparse context.")

    async def handle_auditd_msg(self):
        # Auditd messages are newline-terminated
        data = await self.audis_reader.readline()
        write_msg(data)
        await self.parse_audit_line(data)

        # Monitor pending queue depth and warn if getting high
        # TODO: Add alert messages
        queue_depth = len(self.pending_queue)
        if queue_depth >= ALERT_QUEUE_DEPTH:
            diag_logger.critical("Pending queue depth critical: %d messages queued", queue_depth)
        elif queue_depth >= ALERT_QUEUE_DEPTH * 0.75:
            diag_logger.warning("Pending queue depth high: %d messages queued", queue_depth)

    def __setup_signal_handlers(self):
        self.loop.add_signal_handler(signal.SIGTERM, self.terminate)
        self.loop.add_signal_handler(signal.SIGINT, self.terminate)

    async def run(self):
        diag_logger.info("Starting audit handler main loop")
        await self.__setup_reader()
        self.__setup_signal_handlers()
        diag_logger.info("Audit handler ready (audispd=%r, syslog=%r)", self.audis_path, self.syslog_path)

        # The auditd systemd unit upholds this script and
        # so exit run loop if we get EOF. When auditd comes
        # back it will start this script back up.
        while self.audis_reader is not None and not self.audis_reader.at_eof():
            await self.handle_auditd_msg()

        diag_logger.warning("EOF received from audispd socket, stopping main loop")

        # It's possible that auditd has stopped and syslog-ng isn't in
        # a good state. Write out the recovery file and hope for happier
        # times after a service restart.
        await self.loop.run_in_executor(None, self.__write_recovery_file)


def _is_enterprise() -> bool | None:
    """Single attempt to check enterprise status. Returns None on any error."""
    try:
        with Client() as c:
            return c.call('system.is_enterprise')
    except Exception:
        return None


def _wait_for_enterprise_on_startup() -> bool:
    """
    Retries enterprise check until middlewared responds or timeout expires.
    Returns True (enterprise), False (CE), defaults to False on timeout.
    """
    deadline = time.monotonic() + ENTERPRISE_CHECK_TIMEOUT
    while time.monotonic() < deadline:
        result = _is_enterprise()
        if result is not None:
            diag_logger.info("Enterprise check: is_enterprise=%r", result)
            return result
        diag_logger.debug(
            "Middlewared not yet available, retrying in %ds", ENTERPRISE_CHECK_INTERVAL
        )
        time.sleep(ENTERPRISE_CHECK_INTERVAL)

    diag_logger.warning(
        "Could not reach middlewared within %ds. Defaulting to CE (no-op).",
        ENTERPRISE_CHECK_TIMEOUT
    )
    return False


def _ce_noop_loop() -> None:
    """
    Block indefinitely on CE systems. Polls for a license periodically so
    that if one is installed the handler activates without a manual restart.
    Returns when system.is_enterprise becomes True.
    """
    diag_logger.info(
        "Community Edition — kernel audit handler disabled. "
        "Polling every %ds for enterprise license.", ENTERPRISE_RECHECK_INTERVAL
    )
    while True:
        time.sleep(ENTERPRISE_RECHECK_INTERVAL)
        result = _is_enterprise()
        if result is True:
            diag_logger.info("Enterprise license detected. Starting audit handler.")
            return


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
    try:
        if not stat.S_ISSOCK(os.stat(path).st_mode):
            raise RuntimeError(f'{path}: not a socket.')
    except FileNotFoundError:
        raise RuntimeError(f'{path}: socket does not exist')


def __validate_args(args: argparse.Namespace):
    __validate_socket_path(args.audit_socket)


def main():
    args = __process_args()
    __validate_args(args)

    # Set up module-level diagnostic logger before creating handler
    setup_diagnostic_logger()

    if not _wait_for_enterprise_on_startup():
        _ce_noop_loop()
        # Falls through here only when a license is installed mid-run

    loop = asyncio.new_event_loop()
    handler = AuditdHandler(
        args.audit_socket,
        args.syslog_socket,
        args.recovery_file,
        loop
    )
    diag_logger.info("TrueNAS audit handler starting (pid=%d)", os.getpid())
    diag_logger.info(
        "Configuration: audispd=%r, syslog=%r, recovery=%r", args.audit_socket, args.syslog_socket, args.recovery_file
    )

    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(handler.run())
    except Exception:
        diag_logger.exception("Fatal error in main loop.")
        raise
    finally:
        diag_logger.info("Cleaning up and closing event loop")
        loop.close()
        diag_logger.info("Audit handler exited")


if __name__ == '__main__':
    main()

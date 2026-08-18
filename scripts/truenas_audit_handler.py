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

from collections import deque
from middlewared.logger import (
    TNSyslogHandler, TNLog, DEFAULT_LOGFORMAT, AUDIT_HANDLER_LOGFILE, QFORMATTER
)
from middlewared.utils.hardware import get_hardware_class
import socket
from queue import Queue

import truenas_auparse
from truenas_audit_parse import (
    audit_entry_to_json, classify_event,
)
from truenas_audit_parse.constants import AUDITD_LINE_SEPARATOR


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

# Bound each socket read so the daemon can flush libauparse's feed buffer when
# the audit stream goes idle. libauparse holds some event types (single-record
# LOGIN/TTY events, and any event not yet followed by another) in its feed
# buffer until more input arrives, so without a periodic flush those events
# would be delivered late or lost when auditd stops. The interval is far larger
# than the sub-millisecond gap between records of a single event, so a flush
# never splits a multi-record event.
FLUSH_TIMEOUT = 1.0  # seconds

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
        # Flush any event still buffered in libauparse into the logging pipeline
        # before we persist the pending queue to the recovery file.
        self.__flush_auparse()
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
        msgid = event.get('msgid')
        if not msgid:
            diag_logger.warning("Audit event assembled without a msgid; dropping it")
            return

        raw_lines = event.get('raw_lines', [])
        event_type = classify_event(event)

        json_data = audit_entry_to_json(msgid, event_type, raw_lines, parsed=event)
        self.logger.critical(json_data)

    def __flush_auparse(self):
        """Flush libauparse's feed buffer, emitting any fully-assembled event.

        libauparse holds some events in its feed buffer until more input
        arrives (see FLUSH_TIMEOUT). Flushing on idle and at shutdown ensures
        those events are delivered instead of being delayed indefinitely or
        lost when auditd stops. The flush invokes _on_event_ready synchronously
        for any buffered event.
        """
        try:
            self.auparse_ctx.flush()
        except Exception:
            diag_logger.exception("Failed to flush auparse context.")

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
        # Auditd messages are newline-terminated. Bound the read so that when the
        # stream goes idle we flush libauparse, which buffers some event types
        # (LOGIN, TTY, generic records) until the next record arrives.
        try:
            data = await asyncio.wait_for(self.audis_reader.readline(), FLUSH_TIMEOUT)
        except asyncio.TimeoutError:
            # A timeout means no complete line was available; any partial line
            # remains in the reader's buffer for the next read, so flushing here
            # cannot truncate an in-flight record.
            self.__flush_auparse()
            return

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

        # Emit any event libauparse is still buffering before tearing down so
        # the final event of the session is not lost when auditd stops.
        self.__flush_auparse()

        # It's possible that auditd has stopped and syslog-ng isn't in
        # a good state. Write out the recovery file and hope for happier
        # times after a service restart.
        await self.loop.run_in_executor(None, self.__write_recovery_file)


def _should_handle_audit_events() -> bool:
    """
    Kernel audit events are only ingested into the audit database on iX
    hardware, excluding Minis. This reads the chassis rather than the license,
    so no answer here depends on middlewared or the license daemon being up.

    A detection failure is deliberately treated as "yes": an audit trail that
    is silently missing is worse than one collected on a machine that did not
    need it.
    """
    try:
        hardware_class = get_hardware_class()
    except Exception:
        diag_logger.exception(
            "Hardware detection failed. Handling audit events regardless."
        )
        return True

    diag_logger.info(
        "Detected hardware class %r (appliance=%r)",
        str(hardware_class), hardware_class.is_appliance
    )
    return hardware_class.is_appliance


def _idle_forever() -> None:
    """
    Block without exiting on hardware that does not ingest audit events.

    The auditd unit upholds this service, so exiting would simply have systemd
    restart us immediately, in a tight loop. Nothing is polled because the
    chassis cannot change while the system is running.
    """
    diag_logger.info(
        "Not appliance hardware — kernel audit event handling is disabled."
    )
    while True:
        signal.pause()


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

    if not _should_handle_audit_events():
        _idle_forever()

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

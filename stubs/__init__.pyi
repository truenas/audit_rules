# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

from typing import Callable

def parse_event(raw_text: str) -> dict[str, list[dict[str, int | str | dict[str, str]]]]:
    """Parse audit event text using libauparse.

    Takes one or more newline-separated audit records and returns
    a dict with interpreted field values.

    Parameters
    ----------
    raw_text : str
        Raw audit event text (one or more records, newline-separated)

    Returns
    -------
    dict
        {'records': [{'type': int, 'type_name': str, 'fields': {name: value, ...}}, ...]}
    """
    ...

def get_record_type(raw_text: str) -> str:
    """Get the record type name from the first record in raw audit text.

    Parameters
    ----------
    raw_text : str
        Raw audit record text

    Returns
    -------
    str
        Record type name (e.g., 'SYSCALL', 'PATH', 'LOGIN')
    """
    ...

class AuparseContext:
    """Streaming audit event parser using libauparse feed+callback model."""
    def __init__(self, callback: Callable[[dict], None]) -> None: ...
    def feed(self, line: str) -> None: ...
    def flush(self) -> None: ...

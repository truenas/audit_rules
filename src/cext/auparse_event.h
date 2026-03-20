// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) TrueNAS, 2026

#ifndef _AUPARSE_EVENT_H_
#define _AUPARSE_EVENT_H_

#include <Python.h>
#include <auparse.h>

PyObject *do_parse_event(const char *raw_text);
PyObject *do_get_record_type(const char *raw_text);
PyObject *parse_record_fields(auparse_state_t *au);
PyObject *build_event_dict(auparse_state_t *au);

#endif /* _AUPARSE_EVENT_H_ */

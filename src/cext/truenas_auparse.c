// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) TrueNAS, 2026

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "common/includes.h"
#include "auparse_event.h"
#include "auparse_feed.h"

#define MODULE_DOC "TrueNAS audit event parsing via libauparse"

PyDoc_STRVAR(py_parse_event__doc__,
"parse_event(raw_text)\n"
"--\n\n"
"Parse audit event text using libauparse.\n\n"
"Takes one or more newline-separated audit records and returns\n"
"a dict with interpreted field values.\n\n"
"Parameters\n"
"----------\n"
"raw_text : str\n"
"    Raw audit event text (one or more records, newline-separated)\n\n"
"Returns\n"
"-------\n"
"dict\n"
"    {'records': [{'type': int, 'type_name': str, 'fields': {name: value, ...}}, ...]}\n"
);

static PyObject *
py_parse_event(PyObject *self, PyObject *args)
{
	const char *raw_text;

	if (!PyArg_ParseTuple(args, "s", &raw_text))
		return NULL;

	return do_parse_event(raw_text);
}

PyDoc_STRVAR(py_get_record_type__doc__,
"get_record_type(raw_text)\n"
"--\n\n"
"Get the record type name from the first record in raw audit text.\n\n"
"Parameters\n"
"----------\n"
"raw_text : str\n"
"    Raw audit record text\n\n"
"Returns\n"
"-------\n"
"str\n"
"    Record type name (e.g., 'SYSCALL', 'PATH', 'LOGIN')\n"
);

static PyObject *
py_get_record_type(PyObject *self, PyObject *args)
{
	const char *raw_text;

	if (!PyArg_ParseTuple(args, "s", &raw_text))
		return NULL;

	return do_get_record_type(raw_text);
}

static PyMethodDef truenas_auparse_methods[] = {
	{
		.ml_name = "parse_event",
		.ml_meth = (PyCFunction)py_parse_event,
		.ml_flags = METH_VARARGS,
		.ml_doc = py_parse_event__doc__,
	},
	{
		.ml_name = "get_record_type",
		.ml_meth = (PyCFunction)py_get_record_type,
		.ml_flags = METH_VARARGS,
		.ml_doc = py_get_record_type__doc__,
	},
	{ NULL, NULL, 0, NULL }
};

static struct PyModuleDef truenas_auparse_module = {
	PyModuleDef_HEAD_INIT,
	.m_name = "truenas_auparse",
	.m_doc = MODULE_DOC,
	.m_size = -1,
	.m_methods = truenas_auparse_methods,
};

PyMODINIT_FUNC
PyInit_truenas_auparse(void)
{
	PyObject *m;

	if (PyType_Ready(&AuparseContextType) < 0)
		return NULL;

	m = PyModule_Create(&truenas_auparse_module);
	if (m == NULL)
		return NULL;

	Py_INCREF(&AuparseContextType);
	if (PyModule_AddObject(m, "AuparseContext",
			       (PyObject *)&AuparseContextType) < 0) {
		Py_DECREF(&AuparseContextType);
		Py_DECREF(m);
		return NULL;
	}

	return m;
}

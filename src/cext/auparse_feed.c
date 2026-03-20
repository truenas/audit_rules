// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) TrueNAS, 2026

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "common/includes.h"
#include "auparse_feed.h"
#include "auparse_event.h"
#include <auparse.h>
#include <libaudit.h>

typedef struct {
	PyObject_HEAD
	auparse_state_t *au;
	PyObject *py_callback;
} AuparseContextObject;

/*
 * Extract msgid from raw audit text.
 * Looks for "msg=audit(TIMESTAMP:ID)" pattern and returns
 * "audit(TIMESTAMP:ID)" as a Python string, or None if not found.
 */
static PyObject *
extract_msgid(const char *raw_text)
{
	const char *start, *end;

	start = strstr(raw_text, "msg=audit(");
	if (start == NULL)
		Py_RETURN_NONE;

	start += 4; /* skip "msg=" to get "audit(..." */
	end = strchr(start, ')');
	if (end == NULL)
		Py_RETURN_NONE;

	return PyUnicode_FromStringAndSize(start, end - start + 1);
}


/*
 * C callback invoked by auparse_feed() when an event is ready.
 * GIL is held because auparse_feed() is called from Python.
 */
static void
auparse_cb(auparse_state_t *au, auparse_cb_event_t cb_event_type,
           void *user_data)
{
	AuparseContextObject *self = (AuparseContextObject *)user_data;
	PyObject *event_dict = NULL;
	PyObject *records_list = NULL;
	PyObject *raw_lines_list = NULL;
	PyObject *record = NULL;
	PyObject *raw_line = NULL;
	PyObject *msgid = NULL;
	PyObject *call_result = NULL;
	const char *record_text;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	/* If a previous callback already raised, do not process more events */
	if (PyErr_Occurred())
		return;

	event_dict = PyDict_New();
	if (event_dict == NULL)
		return;

	records_list = PyList_New(0);
	if (records_list == NULL)
		goto error;

	raw_lines_list = PyList_New(0);
	if (raw_lines_list == NULL)
		goto error;

	/* Iterate all records in this event */
	if (auparse_first_record(au) < 1)
		goto done;

	/* Extract msgid from the first record's raw text */
	record_text = auparse_get_record_text(au);
	if (record_text != NULL) {
		msgid = extract_msgid(record_text);
	} else {
		msgid = Py_None;
		Py_INCREF(msgid);
	}
	if (msgid == NULL)
		goto error;

	do {
		record = parse_record_fields(au);
		if (record == NULL)
			goto error;

		if (PyList_Append(records_list, record) < 0) {
			Py_DECREF(record);
			goto error;
		}
		Py_DECREF(record);
		record = NULL;

		/* Capture raw line text */
		record_text = auparse_get_record_text(au);
		if (record_text != NULL) {
			raw_line = PyUnicode_FromString(record_text);
		} else {
			raw_line = PyUnicode_FromString("");
		}
		if (raw_line == NULL)
			goto error;

		if (PyList_Append(raw_lines_list, raw_line) < 0) {
			Py_DECREF(raw_line);
			goto error;
		}
		Py_DECREF(raw_line);
		raw_line = NULL;
	} while (auparse_next_record(au) > 0);

done:
	if (PyDict_SetItemString(event_dict, "records", records_list) < 0)
		goto error;
	if (PyDict_SetItemString(event_dict, "raw_lines", raw_lines_list) < 0)
		goto error;

	if (msgid == NULL) {
		msgid = Py_None;
		Py_INCREF(msgid);
	}
	if (PyDict_SetItemString(event_dict, "msgid", msgid) < 0)
		goto error;

	/* Invoke the Python callback */
	call_result = PyObject_CallOneArg(self->py_callback, event_dict);
	if (call_result == NULL) {
		/* Exception set by the callback - will be checked after feed() returns */
		goto error;
	}
	Py_DECREF(call_result);

	Py_DECREF(event_dict);
	Py_DECREF(records_list);
	Py_DECREF(raw_lines_list);
	Py_DECREF(msgid);
	return;

error:
	Py_XDECREF(event_dict);
	Py_XDECREF(records_list);
	Py_XDECREF(raw_lines_list);
	Py_XDECREF(msgid);
	return;
}


static int
AuparseContext_traverse(AuparseContextObject *self, visitproc visit, void *arg)
{
	Py_VISIT(self->py_callback);
	return 0;
}

static int
AuparseContext_clear(AuparseContextObject *self)
{
	Py_CLEAR(self->py_callback);
	return 0;
}


static int
AuparseContext_init(AuparseContextObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"callback", NULL};
	PyObject *callback = NULL;

	/* Bug 2 fix: reinitialisation — clean up previous state first */
	if (self->au != NULL) {
		auparse_destroy(self->au);
		self->au = NULL;
	}
	Py_CLEAR(self->py_callback);

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &callback))
		return -1;

	if (!PyCallable_Check(callback)) {
		PyErr_SetString(PyExc_TypeError,
				"callback must be callable");
		return -1;
	}

	Py_INCREF(callback);
	self->py_callback = callback;

	self->au = auparse_init(AUSOURCE_FEED, NULL);
	if (self->au == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"auparse_init(AUSOURCE_FEED) failed");
		Py_DECREF(callback);
		self->py_callback = NULL;
		return -1;
	}

	auparse_set_escape_mode(self->au, AUPARSE_ESC_RAW);
	auparse_add_callback(self->au, auparse_cb, self, NULL);

	return 0;
}


static void
AuparseContext_dealloc(AuparseContextObject *self)
{
	PyObject_GC_UnTrack(self);
	if (self->au != NULL) {
		auparse_destroy(self->au);
		self->au = NULL;
	}
	Py_XDECREF(self->py_callback);
	self->py_callback = NULL;
	Py_TYPE(self)->tp_free((PyObject *)self);
}


PyDoc_STRVAR(feed__doc__,
"feed(line)\n"
"--\n\n"
"Feed a line of audit text to the parser.\n\n"
"The callback is invoked synchronously when a complete event is assembled.\n"
);

static PyObject *
AuparseContext_feed(AuparseContextObject *self, PyObject *args)
{
	const char *line;
	Py_ssize_t line_len;
	char *buf = NULL;

	if (!PyArg_ParseTuple(args, "s#", &line, &line_len))
		return NULL;

	/* Ensure newline-terminated for auparse_feed */
	if (line_len == 0 || line[line_len - 1] != '\n') {
		buf = PyMem_RawMalloc(line_len + 2);
		if (buf == NULL)
			return PyErr_NoMemory();
		memcpy(buf, line, line_len);
		buf[line_len] = '\n';
		buf[line_len + 1] = '\0';
		auparse_feed(self->au, buf, line_len + 1);
		PyMem_RawFree(buf);
	} else {
		auparse_feed(self->au, line, line_len);
	}

	/* Check if the callback raised an exception */
	if (PyErr_Occurred())
		return NULL;

	Py_RETURN_NONE;
}


PyDoc_STRVAR(flush__doc__,
"flush()\n"
"--\n\n"
"Flush the feed parser, triggering callbacks for any incomplete events.\n"
);

static PyObject *
AuparseContext_flush(AuparseContextObject *self, PyObject *Py_UNUSED(args))
{
	auparse_flush_feed(self->au);

	if (PyErr_Occurred())
		return NULL;

	Py_RETURN_NONE;
}


static PyMethodDef AuparseContext_methods[] = {
	{
		.ml_name = "feed",
		.ml_meth = (PyCFunction)AuparseContext_feed,
		.ml_flags = METH_VARARGS,
		.ml_doc = feed__doc__,
	},
	{
		.ml_name = "flush",
		.ml_meth = (PyCFunction)AuparseContext_flush,
		.ml_flags = METH_NOARGS,
		.ml_doc = flush__doc__,
	},
	{ NULL, NULL, 0, NULL }
};


PyTypeObject AuparseContextType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "truenas_auparse.AuparseContext",
	.tp_basicsize = sizeof(AuparseContextObject),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_doc = "Streaming audit event parser using libauparse feed+callback model.\n"
	           "Accepts a Python callable that is invoked when complete events are assembled.",
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc)AuparseContext_init,
	.tp_dealloc = (destructor)AuparseContext_dealloc,
	.tp_traverse = (traverseproc)AuparseContext_traverse,
	.tp_clear = (inquiry)AuparseContext_clear,
	.tp_methods = AuparseContext_methods,
};

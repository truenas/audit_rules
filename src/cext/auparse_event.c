// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) TrueNAS, 2026

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "common/includes.h"
#include "auparse_event.h"
#include <auparse.h>
#include <libaudit.h>

/*
 * Parse a single record's fields into a Python dict.
 * Caller must hold the GIL. auparse cursor must be positioned on the record.
 *
 * Returns a new reference to a dict: {"type": str, "type_name": str, "fields": {name: value, ...}}
 * Returns NULL with exception set on error.
 */
PyObject *
parse_record_fields(auparse_state_t *au)
{
	PyObject *record_dict = NULL;
	PyObject *fields_dict = NULL;
	PyObject *raw_fields_dict = NULL;
	PyObject *key = NULL;
	PyObject *val = NULL;
	PyObject *raw_val = NULL;
	const char *type_name;
	int record_type;

	record_dict = PyDict_New();
	if (record_dict == NULL)
		return NULL;

	fields_dict = PyDict_New();
	if (fields_dict == NULL)
		goto error;

	raw_fields_dict = PyDict_New();
	if (raw_fields_dict == NULL)
		goto error;

	record_type = auparse_get_type(au);
	type_name = auparse_get_type_name(au);

	/* Set record type as integer */
	val = PyLong_FromLong(record_type);
	if (val == NULL)
		goto error;
	if (PyDict_SetItemString(record_dict, "type", val) < 0)
		goto error;
	Py_CLEAR(val);

	/* Set record type name */
	if (type_name != NULL) {
		val = PyUnicode_FromString(type_name);
	} else {
		val = PyUnicode_FromFormat("UNKNOWN[%d]", record_type);
	}
	if (val == NULL)
		goto error;
	if (PyDict_SetItemString(record_dict, "type_name", val) < 0)
		goto error;
	Py_CLEAR(val);

	/* Iterate fields */
	if (auparse_first_field(au) < 1) {
		/* No fields - just return the dict with empty fields */
		if (PyDict_SetItemString(record_dict, "fields", fields_dict) < 0)
			goto error;
		if (PyDict_SetItemString(record_dict, "raw_fields", raw_fields_dict) < 0)
			goto error;
		Py_DECREF(fields_dict);
		Py_DECREF(raw_fields_dict);
		return record_dict;
	}

	do {
		const char *field_name = auparse_get_field_name(au);
		const char *field_value = auparse_interpret_field(au);
		const char *raw_field_value = auparse_get_field_str(au);
		size_t fv_len;

		if (field_name == NULL || field_value == NULL)
			continue;

		key = PyUnicode_FromString(field_name);
		if (key == NULL)
			goto error;

		/*
		 * auparse_interpret_field() with AUPARSE_ESC_RAW returns
		 * quoted strings for resolved UID-type fields (e.g.
		 * "sharinguser" instead of sharinguser). Strip the outer
		 * double-quotes so consumers get bare values matching the
		 * old hand-rolled parser's behavior.
		 */
		fv_len = strlen(field_value);
		if (fv_len >= 2 &&
		    field_value[0] == '"' &&
		    field_value[fv_len - 1] == '"') {
			val = PyUnicode_FromStringAndSize(
				field_value + 1, fv_len - 2);
		} else {
			val = PyUnicode_FromString(field_value);
		}
		if (val == NULL)
			goto error;

		if (PyDict_SetItem(fields_dict, key, val) < 0)
			goto error;
		Py_CLEAR(val);

		/* Store raw (uninterpreted) field value */
		if (raw_field_value != NULL) {
			raw_val = PyUnicode_FromString(raw_field_value);
			if (raw_val == NULL)
				goto error;
			if (PyDict_SetItem(raw_fields_dict, key, raw_val) < 0)
				goto error;
			Py_CLEAR(raw_val);
		}

		Py_CLEAR(key);
	} while (auparse_next_field(au) > 0);

	if (PyDict_SetItemString(record_dict, "fields", fields_dict) < 0)
		goto error;
	if (PyDict_SetItemString(record_dict, "raw_fields", raw_fields_dict) < 0)
		goto error;

	Py_DECREF(fields_dict);
	Py_DECREF(raw_fields_dict);
	return record_dict;

error:
	Py_XDECREF(record_dict);
	Py_XDECREF(fields_dict);
	Py_XDECREF(raw_fields_dict);
	Py_XDECREF(key);
	Py_XDECREF(val);
	Py_XDECREF(raw_val);
	return NULL;
}


/*
 * Build event dict from an already-initialized auparse_state_t.
 * Iterates all records and returns {"records": [...]}.
 * Returns NULL with exception set on error.
 */
PyObject *
build_event_dict(auparse_state_t *au)
{
	PyObject *result = NULL;
	PyObject *records_list = NULL;
	PyObject *record = NULL;

	result = PyDict_New();
	if (result == NULL)
		return NULL;

	records_list = PyList_New(0);
	if (records_list == NULL)
		goto cleanup;

	/* Position on first record */
	if (auparse_first_record(au) < 1) {
		/* No records found - return empty list */
		if (PyDict_SetItemString(result, "records", records_list) < 0)
			goto cleanup;
		Py_DECREF(records_list);
		return result;
	}

	do {
		record = parse_record_fields(au);
		if (record == NULL)
			goto cleanup;

		if (PyList_Append(records_list, record) < 0) {
			Py_DECREF(record);
			goto cleanup;
		}
		Py_DECREF(record);
		record = NULL;
	} while (auparse_next_record(au) > 0);

	if (PyDict_SetItemString(result, "records", records_list) < 0)
		goto cleanup;

	Py_DECREF(records_list);
	return result;

cleanup:
	Py_XDECREF(result);
	Py_XDECREF(records_list);
	return NULL;
}


/*
 * parse_event(raw_text) -> dict
 *
 * Parse one or more audit records (newline-separated) using libauparse.
 *
 * Returns: {"records": [{"type": int, "type_name": str, "fields": {name: value}}, ...]}
 */
PyObject *
do_parse_event(const char *raw_text)
{
	auparse_state_t *au = NULL;
	PyObject *result = NULL;
	char *buf = NULL;
	size_t len;

	/*
	 * auparse_init(AUSOURCE_BUFFER) requires newline-terminated input.
	 * Ensure the buffer ends with a newline.
	 */
	len = strlen(raw_text);
	if (len == 0 || raw_text[len - 1] != '\n') {
		buf = PyMem_RawMalloc(len + 2);
		if (buf == NULL) {
			PyErr_NoMemory();
			return NULL;
		}
		memcpy(buf, raw_text, len);
		buf[len] = '\n';
		buf[len + 1] = '\0';
		raw_text = buf;
	}

	/* Initialize auparse from buffer - this does the heavy parsing */
	Py_BEGIN_ALLOW_THREADS
	au = auparse_init(AUSOURCE_BUFFER, raw_text);
	Py_END_ALLOW_THREADS

	if (au == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"auparse_init failed");
		PyMem_RawFree(buf);
		return NULL;
	}

	/* Use RAW escape mode to avoid mangling */
	auparse_set_escape_mode(au, AUPARSE_ESC_RAW);

	result = build_event_dict(au);

	Py_BEGIN_ALLOW_THREADS
	auparse_destroy(au);
	Py_END_ALLOW_THREADS
	PyMem_RawFree(buf);
	return result;
}


/*
 * get_record_type(raw_text) -> str
 *
 * Lightweight extraction of just the record type from the first record.
 */
PyObject *
do_get_record_type(const char *raw_text)
{
	auparse_state_t *au = NULL;
	PyObject *result = NULL;
	const char *type_name;
	char *buf = NULL;
	size_t len;
	const char *original_raw = raw_text;

	/* Ensure newline-terminated input for auparse */
	len = strlen(raw_text);
	if (len == 0 || raw_text[len - 1] != '\n') {
		buf = PyMem_RawMalloc(len + 2);
		if (buf == NULL) {
			PyErr_NoMemory();
			return NULL;
		}
		memcpy(buf, raw_text, len);
		buf[len] = '\n';
		buf[len + 1] = '\0';
		raw_text = buf;
	}

	Py_BEGIN_ALLOW_THREADS
	au = auparse_init(AUSOURCE_BUFFER, raw_text);
	Py_END_ALLOW_THREADS

	if (au == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"auparse_init failed");
		PyMem_RawFree(buf);
		return NULL;
	}

	if (auparse_first_record(au) < 1) {
		/* Fallback for records like EOE with no parseable fields */
		if (strncmp(original_raw, "type=", 5) == 0) {
			const char *start = original_raw + 5;
			const char *end = strchr(start, ' ');
			if (end != NULL) {
				result = PyUnicode_FromStringAndSize(start, end - start);
				goto cleanup;
			}
		}
		PyErr_SetString(PyExc_ValueError,
				"No records found in input");
		goto cleanup;
	}

	type_name = auparse_get_type_name(au);
	if (type_name != NULL) {
		result = PyUnicode_FromString(type_name);
	} else {
		result = PyUnicode_FromFormat("UNKNOWN[%d]",
					     auparse_get_type(au));
	}

cleanup:
	Py_BEGIN_ALLOW_THREADS
	auparse_destroy(au);
	Py_END_ALLOW_THREADS
	PyMem_RawFree(buf);
	return result;
}

// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) TrueNAS, 2026

#ifndef _INCLUDES_H_
#define _INCLUDES_H_
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#define __STRING(x) #x
#define __STRINGSTRING(x) __STRING(x)
#define __LINESTR__ __STRINGSTRING(__LINE__)
#define __location__ __FILE__ ":" __LINESTR__
#endif /* _INCLUDES_H_ */

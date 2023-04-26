/* Copyright 2022 The ChromiumOS Authors.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

static const char* const error_str = "ERROR";

void putnstr(const char* s, uint32_t n);

int printf(const char* format, ...) {
    va_list args;
    char str[256];
    int res;
    va_start(args, format);
    res = vsnprintf(str, sizeof(str), format, args);
    va_end(args);
    if (res > 0)
        putnstr(str, res);
    else
        putnstr(error_str, sizeof(error_str));

    return res;
}

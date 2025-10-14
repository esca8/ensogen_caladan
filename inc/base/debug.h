/*
 * debug.h - configurable debug printing macros
 */

#pragma once

#include <stdio.h>

/* Set to 1 to enable debug prints, 0 to disable */
#ifndef DEBUG_PRINT_ENABLED
#define DEBUG_PRINT_ENABLED 0
#endif

#if DEBUG_PRINT_ENABLED
#define PRINT_DBG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define PRINT_DBG(fmt, ...) do { } while (0)
#endif

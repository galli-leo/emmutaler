#ifndef __VERSION_H
#define __VERSION_H

#include "config.h"

// Helper for STR macro.
#define STR_HELPER(x) #x
// Macro to convert argument to string.
#define STR(x) STR_HELPER(x)

// Mostly for testing, if major version not defined, define our own version here.
// Uses the one from A13 dump.
#ifndef IBOOT_MAJOR

#define IBOOT_MAJOR 4479
#define IBOOT_ZERO1 0
#define IBOOT_ZERO2 0
#define IBOOT_MINOR 100
#define IBOOT_PATCH 4
#endif

// String of the iboot version.
#define IBOOT_VERSION STR(IBOOT_MAJOR) "." STR(IBOOT_ZERO1) "." STR(IBOOT_ZERO2) "." STR(IBOOT_MINOR) "." STR(IBOOT_PATCH)
#define CHIP_STR "t"STR(IBOOT_CHIP)"si"

/*
    Compares two numbers.
    Returns <0 if a < b
    Returns 0 if a = b
    Returns >0 if a > b            
*/
#define COMPARE_NUM(a, b) (a - b)

// Compares two numbers, if they are equal, returns next.
#define COMPARE_NUM_MULTI(a, b, next) (COMPARE_NUM(a, b) ? COMPARE_NUM(a, b) : next)

#define IBOOT_COMPARE_MULTI(val, name, next) (COMPARE_NUM_MULTI(IBOOT_ ##name, val, next))
/*
    Compares the given iboot version to the actual iboot version.
    This should not really be used, but rather the version with variable amount of arguments.
    Since it will choose reasonable default values.
    This function has the same return value as COMPARE_NUM.            
*/
#define IBOOT_COMPARE_INTERNAL(major, zero1, zero2, minor, patch) IBOOT_COMPARE_MULTI(major, MAJOR, IBOOT_COMPARE_MULTI(zero1, ZERO1, IBOOT_COMPARE_MULTI(zero2, ZERO2, IBOOT_COMPARE_MULTI(minor, MINOR, IBOOT_COMPARE_MULTI(patch, PATCH, 0)))))

#define IBOOT_COMPARE3(major, minor, patch) IBOOT_COMPARE_INTERNAL(major, 0, 0, minor, patch)
#define IBOOT_COMPARE2(major, minor) IBOOT_COMPARE3(major, minor, 0)
#define IBOOT_COMPARE1(major) IBOOT_COMPARE2(major, 0)

#define GET_MACRO(_1,_2,_3,NAME,...) NAME
#define IBOOT_COMPARE(...) (GET_MACRO(__VA_ARGS__, IBOOT_COMPARE3, IBOOT_COMPARE2, IBOOT_COMPARE1)(__VA_ARGS__))

#define IBOOT_GEQ(...) (IBOOT_COMPARE(__VA_ARGS__) >= 0)
#define IBOOT_LEQ(...) (IBOOT_COMPARE(__VA_ARGS__) <= 0)
#define IBOOT_LESS(...) (IBOOT_COMPARE(__VA_ARGS__) < 0)
#define IBOOT_GREATER(...) (IBOOT_COMPARE(__VA_ARGS__) > 0)
#define IBOOT_EQUAL(...) (IBOOT_COMPARE(__VA_ARGS__) == 0)

#endif /* __VERSION_H */

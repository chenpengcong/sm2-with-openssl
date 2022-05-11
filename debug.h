#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>

/* 开启DEBUG模式, 打印错误日志 */
#define DEBUG

#ifdef DEBUG
#define DEBUG_ACTIVE 1
#else
#define DEBUG_ACTIVE 0
#endif /* DEBUG */

#define TRACE(fmt, ...) \
    do { \
        if (DEBUG_ACTIVE) printf("%s:%d:%s():" fmt, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
    } while(0)

#endif /* DEBUG_H */
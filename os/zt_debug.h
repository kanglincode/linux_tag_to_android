/*
 * zt_debug.h
 *
 * used for debug
 *
 * Author: pansiwei
 *
 * Copyright (c) 2021 Shandong ZTop Microelectronics Co., Ltd
 *
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */
#ifndef __ZT_DEBUG_H__
#define __ZT_DEBUG_H__

#ifndef ZT_DEBUG_LEVEL
#define ZT_DEBUG_LEVEL   0
#endif

#define ZT_DEBUG_DEBUG         0x01U
#define ZT_DEBUG_INFO          0x02U
#define ZT_DEBUG_WARN          0x04U
#define ZT_DEBUG_ERROR         0x08U
#define ZT_DEBUG_MASK          0x0FU

#ifdef __linux__

#define KERN_LEVELS         KERN_ALERT /* this use to set printk funcation output
                                          level with specify level. the set value
                                          should highter than system default console
                                          level(usually equal to KERN_WARNING). */

/*
 * The color for terminal (foreground)
 * BLACK    30
 * RED      31
 * GREEN    32
 * YELLOW   33
 * BLUE     34
 * PURPLE   35
 * CYAN     36
 * WHITE    37
 */
#ifdef ZT_DEBUG_COLOR
#define _ZT_DEBUG_HDR(lvl_name, color_n)    \
    printk(KERN_LEVELS "\033["#color_n"m["lvl_name"]")
#define _ZT_DEBUG_END   printk("\033[0m\n")
#else
#define _ZT_DEBUG_HDR(lvl_name, color_n)   printk(KERN_LEVELS "["lvl_name"]")
#define _ZT_DEBUG_END   printk("\n")
#endif

#if (ZT_DEBUG_LEVEL & ZT_DEBUG_DEBUG)
#define LOG_D(fmt, ...)   do {  _ZT_DEBUG_HDR("D", 0);   \
        printk(fmt, ##__VA_ARGS__); \
        _ZT_DEBUG_END;  \
    }while(0)
#else
#define LOG_D(fmt, ...)
#endif

#if (ZT_DEBUG_LEVEL & ZT_DEBUG_INFO)
#define LOG_I(fmt, ...)   do {  _ZT_DEBUG_HDR("I", 32);   \
        printk(fmt, ##__VA_ARGS__); \
        _ZT_DEBUG_END;  \
    }while(0)
#else
#define LOG_I(fmt, ...)
#endif

#if (ZT_DEBUG_LEVEL & ZT_DEBUG_WARN)
#define LOG_W(fmt, ...)   do {  _ZT_DEBUG_HDR("W", 33);   \
        printk(fmt, ##__VA_ARGS__); \
        _ZT_DEBUG_END;  \
    }while(0)
#else
#define LOG_W(fmt, ...)
#endif

#if (ZT_DEBUG_LEVEL & ZT_DEBUG_ERROR)
#define LOG_E(fmt, ...)   do {  _ZT_DEBUG_HDR("E", 31);   \
        printk(fmt, ##__VA_ARGS__); \
        _ZT_DEBUG_END;  \
    }while(0)
#else
#define LOG_E(fmt, ...)
#endif

#define ZT_ASSERT(EX)                                     \
    if (!(EX))                                                    \
    {                                                             \
        LOG_E("#EX assertion failed at function:%s, line number:%d \n", __FUNCTION__, __LINE__);\
        BUG();                                                 \
    }

#include "zt_os_api.h"
static zt_inline void log_array(void *ptr, zt_u16 len)
{
    zt_u16 i = 0;
    zt_u16 num;
    zt_u8 *pdata = ptr;

#define NUM_PER_LINE    8
    printk(KERN_LEVELS "\r\n");
    //  for (i = 0, num = len / NUM_PER_LINE; i < num;
    //         i++, pdata = &pdata[i * NUM_PER_LINE]) {
    for (i = 0, num = len / NUM_PER_LINE; i < num; i++, pdata += 8)
    {
        printk(KERN_LEVELS "%02X %02X %02X %02X %02X %02X %02X %02X\r\n",
               pdata[0], pdata[1], pdata[2], pdata[3],
               pdata[4], pdata[5], pdata[6], pdata[7]);
    }
    num = len % NUM_PER_LINE;
    if (num)
    {
        for (i = 0; i < num; i++)
        {
            printk(KERN_LEVELS "%02X", pdata[i]);
        }
    }
    printk(KERN_LEVELS "\r\n");
}

#endif

#endif      /* END OF __ZT_DEBUG_H__ */

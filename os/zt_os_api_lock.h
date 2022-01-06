/*
 * zt_os_api_lock.h
 *
 * used for .....
 *
 * Author: zenghua
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
#ifndef __ZT_OS_API_LOCK_H__
#define __ZT_OS_API_LOCK_H__

typedef spinlock_t              zt_lock_spin;

typedef struct
{
    zt_lock_spin lock;
    zt_irq val_irq;
} zt_lock_spin_t;
typedef enum
{
    ZT_LOCK_TYPE_NONE = 0,
    ZT_LOCK_TYPE_MUTEX,
    ZT_LOCK_TYPE_SPIN,
    ZT_LOCK_TYPE_BH,
    ZT_LOCK_TYPE_IRQ,

    ZT_LOCK_TYPE_MAX,
} zt_lock_type_e;
typedef struct
{
    union
    {
        zt_lock_mutex lock_mutex;
        zt_lock_spin_t lock_spin;
    };
    zt_lock_type_e lock_type;
} zt_lock_t;


void zt_lock_lock(zt_lock_t *plock);
zt_s32 zt_lock_trylock(zt_lock_t *plock);
void zt_lock_unlock(zt_lock_t *plock);
void zt_lock_init(zt_lock_t *plock, zt_lock_type_e lock_type);
void zt_lock_term(zt_lock_t *plock);

#endif


/*
 * zt_os_api_file.c
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
/* include */
#include "zt_os_api.h"

/* macro */

/* type */

/* function declaration */

zt_file *zt_os_api_file_open(const zt_s8 *path)
{
    zt_file *filp = NULL;
    zt_s32 err = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp))
    {
        err = PTR_ERR(filp);
        return NULL;
    }
#else
    mm_segment_t oldfs;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, O_RDONLY, 0);
    set_fs(oldfs);
    if (IS_ERR(filp))
    {
        err = PTR_ERR(filp);
        return NULL;
    }
#endif

    return filp;
}

zt_s32 zt_os_api_file_read(zt_file *file, loff_t offset,
                           zt_u8 *data, zt_u32 size)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
    mm_segment_t oldfs;
#endif
    zt_s32 ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 114)
    ret = kernel_read(file, data, size, &offset);
#else
    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
#endif
    return ret;
}

size_t zt_os_api_file_size(zt_file *file)
{
    return vfs_llseek(file, 0L, SEEK_END);
}


zt_inline void zt_os_api_file_close(zt_file *file)
{
    filp_close(file, NULL);
}


/*
 * proc.h
 *
 * used for print debugging information
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
#ifndef __PROC_H__
#define __PROC_H__

#include "ndev_linux.h"

#define zt_register_proc_interface(_name, _show, _write) \
    { .name = _name, .show = _show, .write = _write}
#define zt_print_seq seq_printf

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
#define zt_proc_net proc_net
#else
extern struct net init_net;
#define zt_proc_net init_net.proc_net
#endif

struct zt_proc_handle
{
    zt_s8 *name;
    zt_s32(*show)(struct seq_file *, void *);
    ssize_t (*write)(struct file *file, const char __user *buffer, size_t count,
                     loff_t *pos, void *data);
};


#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
#define PDE_DATA(inode) PDE((inode))->data
#define proc_get_parent_data(inode) PDE((inode))->parent->data
#endif

typedef struct
{
    void *hif_info;
    struct proc_dir_entry *proc_root;
    zt_s8 proc_name[32];
} zt_proc_st;

zt_s32 zt_proc_init(void *nic_info);
void zt_proc_term(void *nic_info);

#endif


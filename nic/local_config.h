/*
 * local_config.h
 *
 * used for local information
 *
 * Author: songqiang
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
#ifndef __LOCAL_CFG_H__
#define __LOCAL_CFG_H__


typedef enum
{
    ZT_AUTO_MODE,       /* Let the driver decides */
    ZT_ADHOC_MODE,      /* Single cell network */
    ZT_INFRA_MODE,      /* Multi cell network, roaming, ... */
    ZT_MASTER_MODE,     /* Synchronisation master or Access Point */
    ZT_REPEAT_MODE,     /* Wireless Repeater (forwarder) */
    ZT_SECOND_MODES,    /* Secondary master/repeater (backup) */
    ZT_MONITOR_MODE,    /* Passive monitor (listen only) */
    ZT_MESH_MODE,       /* Mesh (IEEE 802.11s) network */
} sys_work_mode_e;


typedef struct
{
    sys_work_mode_e     work_mode;
    zt_u8               channel;
    CHANNEL_WIDTH       bw;
    zt_bool             adhoc_master;
    zt_u8               ssid[32];
    zt_u8               channel_plan;
    zt_u8               ba_enable;
    zt_u8               scan_ch_to; /* scan timeout on channel in ms */
    zt_u8
    scan_prb_times; /* scan probe request times on each channel */
    zt_u8               scan_que_deep; /* wlan_mgmt scan queue deep */
    zt_u8
    scan_que_node_ttl; /* wlan_mgmt scan queue node TTL(time to life) */
} local_info_st;

#define NIC_INFO_2_WORK_MODE(nic) ((local_info_st *)nic->local_info)->work_mode

zt_s32 zt_local_cfg_init(nic_info_st *nic_info);
zt_s32 zt_local_cfg_term(nic_info_st *nic_info);
zt_s32 zt_local_cfg_set_default(nic_info_st *nic_info);
zt_s32 zt_local_cfg_get_default(nic_info_st *nic_info);
sys_work_mode_e zt_local_cfg_get_work_mode(nic_info_st *pnic_info);

#endif

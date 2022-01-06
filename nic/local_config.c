/*
 * local_config.c
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
#undef ZT_DEBUG_LEVEL
#define ZT_DEBUG_LEVEL (~ZT_DEBUG_DEBUG)
#include "common.h"

static local_info_st default_cfg[] =
{
    {
        .work_mode  = ZT_AUTO_MODE,
        .channel    = 1,
        .bw         = CHANNEL_WIDTH_20,
        .adhoc_master   = zt_false,
        .ssid        = "SCI-AUTO",
        .channel_plan = ZT_CHPLAN_CHINA,
        .ba_enable = 1,

        .scan_ch_to = 50,
        .scan_prb_times = 3,
        .scan_que_deep = 64,
        .scan_que_node_ttl = 20,
    },
    {
        .work_mode  = ZT_ADHOC_MODE,
        .channel    = 1,
        .bw         = CHANNEL_WIDTH_20,
        .adhoc_master   = zt_false,
        .ssid        = "SCI-ADHOC",
        .channel_plan = ZT_CHPLAN_CHINA,
        .ba_enable = 1,

        .scan_ch_to = 50,
        .scan_prb_times = 3,
        .scan_que_deep = 64,
        .scan_que_node_ttl = 20,
    },
    {
        .work_mode  = ZT_INFRA_MODE,
        .channel    = 1,
        .bw         = CHANNEL_WIDTH_20,
        .adhoc_master   = zt_false,
        .ssid        = "SCI-STA",
        .channel_plan = ZT_CHPLAN_CHINA,
        .ba_enable = 1,

        .scan_ch_to = 50,
        .scan_prb_times = 3,
        .scan_que_deep = 64,
        .scan_que_node_ttl = 20,
    },
    {
        .work_mode  = ZT_MASTER_MODE,
        .channel    = 1,
        .bw         = CHANNEL_WIDTH_20,
        .adhoc_master   = zt_false,
        .ssid        = "SCI-AP",
        .channel_plan = ZT_CHPLAN_CHINA,
        .ba_enable = 1,

        .scan_ch_to = 50,
        .scan_prb_times = 3,
        .scan_que_deep = 64,
        .scan_que_node_ttl = 20,
    },
    {
        .work_mode  = ZT_REPEAT_MODE,
        .channel    = 1,
        .bw         = CHANNEL_WIDTH_20,
        .adhoc_master   = zt_false,
        .ssid        = "SCI-REPEAT",
        .channel_plan = ZT_CHPLAN_CHINA,
        .ba_enable = 1,

        .scan_ch_to = 50,
        .scan_prb_times = 3,
        .scan_que_deep = 64,
        .scan_que_node_ttl = 20,
    },
    {
        .work_mode  = ZT_SECOND_MODES,
        .channel    = 1,
        .bw         = CHANNEL_WIDTH_20,
        .adhoc_master   = zt_false,
        .ssid        = "SCI-SECOND",
        .channel_plan = ZT_CHPLAN_CHINA,
        .ba_enable = 1,

        .scan_ch_to = 50,
        .scan_prb_times = 3,
        .scan_que_deep = 64,
        .scan_que_node_ttl = 20,
    },
    {
        .work_mode  = ZT_MONITOR_MODE,
        .channel    = 1,
        .bw         = CHANNEL_WIDTH_20,
        .adhoc_master   = zt_false,
        .ssid        = "SCI-NONITOR",
        .channel_plan = ZT_CHPLAN_CHINA,
        .ba_enable = 1,

        .scan_ch_to = 50,
        .scan_prb_times = 3,
        .scan_que_deep = 64,
        .scan_que_node_ttl = 20,
    },
    {
        .work_mode  = ZT_MESH_MODE,
        .channel    = 1,
        .bw         = CHANNEL_WIDTH_20,
        .adhoc_master   = zt_false,
        .ssid        = "SCI-MESH",
        .channel_plan = ZT_CHPLAN_CHINA,
        .ba_enable = 1,

        .scan_ch_to = 50,
        .scan_prb_times = 3,
        .scan_que_deep = 64,
        .scan_que_node_ttl = 20,
    },

};

zt_s32 zt_local_cfg_init(nic_info_st *nic_info)
{
    nic_info->local_info = (local_info_st *)zt_kzalloc(sizeof(local_info_st));
    if (nic_info->local_info == NULL)
    {
        return -1;
    }
    zt_memcpy(nic_info->local_info, &default_cfg[ZT_INFRA_MODE],
              sizeof(local_info_st));

    return 0;
}

zt_s32 zt_local_cfg_term(nic_info_st *nic_info)
{
    if (nic_info->local_info != NULL)
    {
        zt_kfree(nic_info->local_info);
    }

    return 0;
}


zt_s32 zt_local_cfg_get_default(nic_info_st *nic_info)
{
    local_info_st *local_info = nic_info->local_info;
    hw_info_st *hw_info = nic_info->hw_info;

    if (nic_info->nic_cfg_file_read != NULL)
    {
        if (nic_info->nic_cfg_file_read((void *)nic_info) == 0)
        {
            hw_info->channel_plan = local_info->channel_plan;
            hw_info->ba_enable = local_info->ba_enable;
        }
    }

    /* set channel plan */
    channel_init(nic_info);

    return 0;
}

static zt_s32 rx_config_agg(nic_info_st *nic_info)
{
    zt_s32 ret = 0;

    ret = zt_mcu_set_agg_param(nic_info, 0x8, 0x5, 1);
    if (ret != ZT_RETURN_OK)
    {
        return ZT_RETURN_FAIL;
    }

    return 0;
}

zt_s32 zt_local_cfg_set_default(nic_info_st *nic_info)
{
    local_info_st *local_info = nic_info->local_info;
    zt_s32 ret = 0;

    LOG_D("[LOCAL_CFG] work_mode: %d", local_info->work_mode);
    LOG_D("[LOCAL_CFG] channel: %d", local_info->channel);
    LOG_D("[LOCAL_CFG] bw: %d", local_info->bw);
    LOG_D("[LOCAL_CFG] ssid: %s", local_info->ssid);

    ret = zt_hw_info_set_channnel_bw(nic_info, local_info->channel, local_info->bw,
                                     HAL_PRIME_CHNL_OFFSET_DONT_CARE);
    if (ret != ZT_RETURN_OK)
    {
        return ZT_RETURN_FAIL;
    }
    ret = zt_mcu_handle_rf_iq_calibrate(nic_info, local_info->channel);
    if (ret != ZT_RETURN_OK)
    {
        return ZT_RETURN_FAIL;
    }

    ret = zt_mcu_update_thermal(nic_info);
    if (ret != ZT_RETURN_OK)
    {
        return ZT_RETURN_FAIL;
    }

    // cfg sta/ap/adhoc/monitor mode
    ret = zt_mcu_set_op_mode(nic_info, local_info->work_mode);
    if (ret != ZT_RETURN_OK)
    {
        return ZT_RETURN_FAIL;
    }

    rx_config_agg(nic_info);

    return ZT_RETURN_OK;
}


sys_work_mode_e zt_local_cfg_get_work_mode(nic_info_st *pnic_info)
{
    local_info_st *plocal = (local_info_st *)pnic_info->local_info;
    return plocal->work_mode;
}



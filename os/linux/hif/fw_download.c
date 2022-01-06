/*
 * fw_download.c
 *
 * used for fireware download after system power on
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
#define ZT_DEBUG_LEVEL  (~ZT_DEBUG_DEBUG)
#include "common.h"
#include "hif.h"
#include "hw_ctrl.h"
#include "fw_download.h"

/* macro */
#define FWDL_DBG(fmt, ...)      LOG_D("[%s:%d]"fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FWDL_INFO(fmt, ...)     LOG_I("[%s:%d]"fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FWDL_WARN(fmt, ...)     LOG_W("[%s:%d]"fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FWDL_ERROR(fmt, ...)    LOG_E("[%s:%d]"fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

/* function declaration */
static zt_s32 fwdl_cmd_get_status(hif_node_st *hif_node)
{
    /*test base on hisilicon platform, it would need 25000*/
    zt_u32 ret = 0;
    zt_u32 data = 0;
    zt_u32 tryCnt = 0;
    zt_timer_t timer;
    zt_u32 t_delta = 0;

    // set mailbox zt_s32 finish
    ret = hif_io_write32(hif_node, ZT_MAILBOX_INT_FINISH, 0x12345678);
    if (ZT_RETURN_FAIL == ret)
    {
        LOG_E("[%s] ZT_MAILBOX_INT_FINISH failed, check!!!", __func__);
        return ret;
    }

    // set mailbox triger zt_s32
    ret = hif_io_write8(hif_node, ZT_MAILBOX_REG_INT, 1);
    if (ZT_RETURN_FAIL == ret)
    {
        LOG_E("[%s] ZT_MAILBOX_REG_INT failed, check!!!", __func__);
        return ret;
    }

    do
    {
        zt_s32 err = 0;

        data = hif_io_read32(hif_node, ZT_MAILBOX_INT_FINISH, &err);
        if (err)
        {
            LOG_E("[%s] read failed,err:%d", __func__, err);
            break;
        }
        if (HIF_USB == hif_node->hif_type && 0x55 == data)
        {
            return ZT_RETURN_OK;

        }
        else if (HIF_SDIO == hif_node->hif_type && 0x000000aa == data)
        {
            return ZT_RETURN_OK;
        }

        zt_timer_set(&timer, t_delta += (tryCnt++ < 3));
        while (!zt_timer_expired(&timer));
    } while ((tryCnt - 1) * 3 < 1000); /* totall time(ms) = (x-1)*3 */

    LOG_I("timeout !!!  data:0x%x", data);
    return ZT_RETURN_FAIL;
}


static zt_s32 fwdl_wait_fw_startup(hif_node_st *hif_node)
{
    /* get mcu feedback */
    if (fwdl_cmd_get_status(hif_node) < 0)
    {
        LOG_E("===>zt_mcu_cmd_get_status error, exit");
        return ZT_RETURN_FAIL;
    }

    return ZT_RETURN_OK;
}

zt_s32 zt_fw_download(void *node)
{
    hif_node_st *hif_node = node;
    hif_mngent_st *hif_mngent = hif_mngent_get();
    zt_u8 value8;

    FWDL_INFO("start");
    zt_hw_mcu_disable(hif_node);
    zt_hw_mcu_enable(hif_node);

    /* todo: rom select is used for debug with s9083 IC, in the future when
    debug with ZT9101xV20 IC need bypass this logic!!! */
#if 1
    /* disable 51
    If 51 is still running when switching ROM, it may cause 51 to enter an
    abnormal state the new version EVB will remove this code, because we
    select default ROM in efuse */
    hif_io_read(hif_node, 0, 0x03, &value8, sizeof(value8));
    value8 &= ~ ZT_BIT(2);
    hif_io_write(hif_node, 0, 0x03, &value8, sizeof(value8));

    /* ROM select */
    if (hif_mngent->fw_rom_type)
    {
        FWDL_DBG("new rom select");

        hif_io_read(hif_node, 0, 0xf4, &value8, sizeof(value8));
        value8 &= 0xFE;
        hif_io_write(hif_node, 0, 0xf4, &value8, sizeof(value8));
        hif_io_read(hif_node, 0, 0xf4, &value8, sizeof(value8));
    }
    else
    {
        FWDL_DBG("old rom select");

        hif_io_read(hif_node, 0, 0xf4, &value8, sizeof(value8));
        value8 |= 0x01;
        hif_io_write(hif_node, 0, 0xf4, &value8, sizeof(value8));
        hif_io_read(hif_node, 0, 0xf4, &value8, sizeof(value8));
    }

    /* enable 51 */
    hif_io_read(hif_node, 0, 0x03, &value8, sizeof(value8));
    value8 |= ZT_BIT(2);
    hif_io_write(hif_node, 0, 0x03, &value8, sizeof(value8));
#endif

    {
        zt_timer_t timer;

        FWDL_INFO("fw downloading.....");
        zt_timer_set(&timer, 0);

        if (hif_write_firmware(hif_node, 0,
                               (zt_u8 *)hif_mngent->fw0, hif_mngent->fw0_size))
        {
            return -1;
        }

        if (hif_write_firmware(hif_node, 1,
                               (zt_u8 *)hif_mngent->fw1, hif_mngent->fw1_size))
        {
            return -1;
        }

        FWDL_DBG("===>fw download elapsed: %d ms", zt_timer_elapsed(&timer));
    }

    /* fw startup */
    if (zt_hw_mcu_startup(hif_node) != ZT_RETURN_OK)
    {
        FWDL_ERROR("===>zt_hw_mcu_startup error, exit!!");
        return ZT_RETURN_FAIL;
    }

    /* wait fw status */
    if (fwdl_wait_fw_startup(hif_node))
    {
        FWDL_ERROR("===>dsp_run_startup error, exit!!");
        return ZT_RETURN_FAIL;
    }

    FWDL_INFO("end");

    return 0;
}



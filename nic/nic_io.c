/*
 * nic_io.c
 *
 * used for nic io read or write
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
#undef ZT_DEBUG_LEVEL
#define ZT_DEBUG_LEVEL (~ZT_DEBUG_DEBUG)
#include "common.h"

zt_u8 zt_io_read8(const nic_info_st *nic_info, zt_u32 addr, zt_s32 *err)
{
    zt_u8 value;
    zt_s32 ret = 0;
    ZT_ASSERT(nic_info != NULL);

    ret = nic_info->nic_read(nic_info->hif_node, 0, addr, (zt_s8 *)&value,
                             sizeof(value));
    if (err)
    {
        *err = ret;
    }

    return value;
}

zt_u16 zt_io_read16(const nic_info_st *nic_info, zt_u32 addr, zt_s32 *err)
{
    zt_u16 value;
    zt_s32 ret = 0;
    ZT_ASSERT(nic_info != NULL);

    ret = nic_info->nic_read(nic_info->hif_node, 0, addr, (zt_s8 *)&value,
                             sizeof(value));
    if (err)
    {
        *err = ret;
    }

    return value;
}

zt_u32 zt_io_read32(const nic_info_st *nic_info, zt_u32 addr, zt_s32 *err)
{
    zt_u32 value = 0;
    zt_s32 ret = 0;
    ZT_ASSERT(nic_info != NULL);

    ret = nic_info->nic_read(nic_info->hif_node, 0, addr, (zt_s8 *)&value,
                             sizeof(value));
    if (err)
    {
        *err = ret;
    }

    return value;
}

zt_s32 zt_io_write8(const nic_info_st *nic_info, zt_u32 addr, zt_u8 value)
{
    ZT_ASSERT(nic_info != NULL);

    return nic_info->nic_write(nic_info->hif_node, 0, addr, (zt_s8 *)&value,
                               sizeof(value));
}

zt_s32 zt_io_write16(const nic_info_st *nic_info, zt_u32 addr, zt_u16 value)
{
    ZT_ASSERT(nic_info != NULL);

    return nic_info->nic_write(nic_info->hif_node, 0, addr, (zt_s8 *)&value,
                               sizeof(value));
}

zt_s32 zt_io_write32(const nic_info_st *nic_info, zt_u32 addr, zt_u32 value)
{
    ZT_ASSERT(nic_info != NULL);

    return nic_info->nic_write(nic_info->hif_node, 0, addr, (zt_s8 *)&value,
                               sizeof(value));
}


zt_s32 zt_io_write_data(const nic_info_st *nic_info, zt_u8 agg_num, zt_s8 *pbuf,
                        zt_u32 len, zt_u32 addr,
                        zt_s32(*callback_func)(void *tx_info, void *param), void *tx_info, void *param)
{
    zt_s32 ret = 0;

    ZT_ASSERT(nic_info != NULL);

    if (nic_info->nic_tx_queue_insert == NULL)
    {
        LOG_E("nic_tx_queue_insert is not register, please check!!");
        return -1;
    }

    ret = nic_info->nic_tx_queue_insert(nic_info->hif_node, agg_num, pbuf, len,
                                        addr,
                                        callback_func, tx_info, param);

    return ret;
}


zt_s32 zt_io_write_data_queue_check(const nic_info_st *nic_info)
{
    ZT_ASSERT(nic_info != NULL);
    if (nic_info->nic_tx_queue_empty == NULL)
    {
        LOG_E("nic_tx_queue_empty is not register, please check!!");
        return -1;
    }

    return nic_info->nic_tx_queue_empty(nic_info->hif_node);
}

zt_s32 zt_io_tx_xmit_wake(const nic_info_st *nic_info)
{
    ZT_ASSERT(nic_info != NULL);
    if (nic_info->nic_tx_wake == NULL)
    {
        LOG_E("nic_tx_wake is not register, please check!!");
        return -1;
    }

    return nic_info->nic_tx_wake((nic_info_st *)nic_info);
}

static zt_s8 *cmd_to_str(zt_s32 cmd)
{
#define c2s(x) #x
    switch (cmd)
    {
        case FUNC_REPLY                                     :
            return c2s(FUNC_REPLY);
        case UMSG_OPS_READ_VERSION                          :
            return c2s(UMSG_OPS_READ_VERSION);
        case UMSG_OPS_HAL_SET_HWREG                         :
            return c2s(UMSG_OPS_HAL_SET_HWREG);
        case UMSG_OPS_HAL_GET_HWREG                         :
            return c2s(UMSG_OPS_HAL_GET_HWREG);
        case UMSG_OPS_HAL_MSG_WDG                           :
            return c2s(UMSG_OPS_HAL_MSG_WDG);
        case UMSG_OPS_HAL_WRITEVAR_MSG                      :
            return c2s(UMSG_OPS_HAL_WRITEVAR_MSG);
        case UMSG_OPS_HAL_READVAR_MSG                       :
            return c2s(UMSG_OPS_HAL_READVAR_MSG);
        case UMSG_OPS_HAL_GET_MSG_STA_INFO                  :
            return c2s(UMSG_OPS_HAL_GET_MSG_STA_INFO);
        case UMSG_OPS_HAL_SYNC_MSG_STA_INFO                 :
            return c2s(UMSG_OPS_HAL_SYNC_MSG_STA_INFO);
        case UMSG_OPS_HAL_CALI_LLC                          :
            return c2s(UMSG_OPS_HAL_CALI_LLC);
        case UMSG_OPS_HAL_PHY_IQ_CALIBRATE                  :
            return c2s(UMSG_OPS_HAL_PHY_IQ_CALIBRATE);
        case UMSG_OPS_HAL_CHNLBW_MODE                       :
            return c2s(UMSG_OPS_HAL_CHNLBW_MODE);
        case UMSG_OPS_HAL_FW_INIT                           :
            return c2s(UMSG_OPS_HAL_FW_INIT);
        case UMSG_OPS_HAL_UPDATE_THERMAL                    :
            return c2s(UMSG_OPS_HAL_UPDATE_THERMAL);
        case UMSG_OPS_HAL_SET_MAC                           :
            return c2s(UMSG_OPS_HAL_SET_MAC);
        case UMSG_OPS_HAL_SET_BSSID                         :
            return c2s(UMSG_OPS_HAL_SET_BSSID);
        case UMSG_OPS_HAL_SET_BCN                           :
            return c2s(UMSG_OPS_HAL_SET_BCN);
        case UMSG_OPS_HW_SET_BASIC_RATE                     :
            return c2s(UMSG_OPS_HW_SET_BASIC_RATE);
        case UMSG_OPS_HW_SET_OP_MODE                        :
            return c2s(UMSG_OPS_HW_SET_OP_MODE);
        case UMSG_OPS_HW_SET_CORRECT_TSF                    :
            return c2s(UMSG_OPS_HW_SET_CORRECT_TSF);
        case UMSG_OPS_HW_SET_MLME_DISCONNECT                :
            return c2s(UMSG_OPS_HW_SET_MLME_DISCONNECT);
        case UMSG_OPS_HW_SET_MLME_SITE                      :
            return c2s(UMSG_OPS_HW_SET_MLME_SITE);
        case UMSG_OPS_HW_SET_MLME_JOIN                      :
            return c2s(UMSG_OPS_HW_SET_MLME_JOIN);
        case UMSG_OPS_HW_SET_DK_CFG                         :
            return c2s(UMSG_OPS_HW_SET_DK_CFG);
        case UMSG_OPS_HAL_SEC_WRITE_CAM                     :
            return c2s(UMSG_OPS_HAL_SEC_WRITE_CAM);
        case UMSG_OPS_HAL_CONTROL_ARS_CMD                   :
            return c2s(UMSG_OPS_HAL_CONTROL_ARS_CMD);
        case UMSG_OPS_HAL_LPS_OPT                           :
            return c2s(UMSG_OPS_HAL_LPS_OPT);
        case UMSG_OPS_HAL_LPS_CONFIG                        :
            return c2s(UMSG_OPS_HAL_LPS_CONFIG);
        case UMSG_OPS_HAL_LPS_SET                           :
            return c2s(UMSG_OPS_HAL_LPS_SET);
        case UMSG_OPS_HAL_LPS_GET                           :
            return c2s(UMSG_OPS_HAL_LPS_GET);
        case UMSG_OPS_HAL_SET_USB_AGG_NORMAL                :
            return c2s(UMSG_OPS_HAL_SET_USB_AGG_NORMAL);
        case UMSG_OPS_MP_EFUSE_GET                          :
            return c2s(UMSG_OPS_MP_EFUSE_GET);
        case UMSG_OPS_MP_USER_INFO                          :
            return c2s(UMSG_OPS_MP_USER_INFO);
        case UMSG_OPS_RESET_CHIP                            :
            return c2s(UMSG_OPS_RESET_CHIP);
        case UMSG_OPS_HAL_DBGLOG_CONFIG                     :
            return c2s(UMSG_OPS_HAL_DBGLOG_CONFIG);
        default:
            LOG_E("Unknown cmd:0x%x", cmd);
            return "Unknown cmd";
    }
}

zt_s32 zt_io_write_cmd_by_mailbox(nic_info_st *nic_info, zt_u32 cmd,
                                  zt_u32 *send_buf, zt_u32 send_len, zt_u32 *recv_buf, zt_u32 recv_len)
{
    zt_s32 ret  = 0;
    zt_u32 mailbox_reg_addr = MAILBOX_ARG_START;
    zt_u8 tryCnt = 0;
    zt_u32 temp_send_len = 0;

    if (nic_info->is_surprise_removed || nic_info->is_driver_stopped)
    {
        return ZT_RETURN_OK;
    }

    nic_mcu_hw_access_lock(nic_info);


    for (tryCnt = 0; tryCnt < 2; tryCnt++)
    {
        temp_send_len = send_len;
        mailbox_reg_addr = MAILBOX_ARG_START;
        ret = zt_io_write32(nic_info, MAILBOX_REG_START, cmd);
        if (ZT_RETURN_FAIL == ret)
        {
            LOG_E("[%s,%d] zt_io_write32 failed cmd:0x%x", __func__, __LINE__, cmd);
            goto exit;

        }
        ret = zt_io_write32(nic_info, mailbox_reg_addr, send_len);
        if (ZT_RETURN_FAIL == ret)
        {
            LOG_E("[%s,%d] zt_io_write32 failed", __func__, __LINE__);
            goto exit;
        }

        mailbox_reg_addr += MAILBOX_WORD_LEN;
        ret = zt_io_write32(nic_info, mailbox_reg_addr, recv_len);
        if (ZT_RETURN_FAIL == ret)
        {
            LOG_E("[%s,%d] zt_io_write32 failed", __func__, __LINE__);
            goto exit;
        }

        mailbox_reg_addr += MAILBOX_WORD_LEN;

        while ((temp_send_len--) && send_buf)
        {
            ret = zt_io_write32(nic_info, mailbox_reg_addr, *send_buf++);
            if (ZT_RETURN_FAIL == ret)
            {
                LOG_E("[%s,%d] zt_io_write32 failed", __func__, __LINE__);
                goto exit;
            }
            mailbox_reg_addr += MAILBOX_WORD_LEN;
        }

        ret = zt_mcu_cmd_get_status(nic_info, cmd);
        if (ZT_RETURN_FAIL == ret)
        {
            if (tryCnt == 0)
            {
                LOG_W("mcu_cmd_get_status failed, try again. cmd:%s", cmd_to_str(cmd));
            }
            else
            {
                LOG_E("mcu_cmd_get_status failed, please check the hardware io. cmd:%s",
                      cmd_to_str(cmd));
                goto exit;
            }
        }
        else if (ZT_RETURN_REMOVED_FAIL == ret)
        {
            LOG_W("[%s,%d] driver or device is removed. cmd:0x%08x,%s", __func__, __LINE__,
                  cmd, cmd_to_str(cmd));
            goto exit;
        }
        else
        {
            break;
        }
    }

    mailbox_reg_addr = MAILBOX_ARG_START;
    if (ret == 0)
    {
        while ((recv_len--) && recv_buf)
        {
            *recv_buf++ = zt_io_read32(nic_info, mailbox_reg_addr, NULL);
            mailbox_reg_addr += MAILBOX_WORD_LEN;
        }
    }

    ret = ZT_RETURN_OK;

exit:
    nic_mcu_hw_access_unlock(nic_info);

    return ret;
}


zt_s32 zt_io_write_cmd_by_mailbox_try(nic_info_st *nic_info, zt_u32 cmd,
                                      zt_u32 *send_buf, zt_u32 send_len, zt_u32 *recv_buf, zt_u32 recv_len)
{
    zt_s32 ret = 0;
    zt_u32 mailbox_reg_addr = MAILBOX_ARG_START;

    if (nic_info->is_surprise_removed || nic_info->is_driver_stopped)
    {
        return ZT_RETURN_OK;
    }

    nic_mcu_hw_access_trylock(nic_info);

    ret = zt_io_write32(nic_info, MAILBOX_REG_START, cmd);
    if (ZT_RETURN_FAIL == ret)
    {
        LOG_E("[%s,%d] zt_io_write32 failed cmd:0x%x", __func__, __LINE__, cmd);
        goto exit;

    }
    ret = zt_io_write32(nic_info, mailbox_reg_addr, send_len);
    if (ZT_RETURN_FAIL == ret)
    {
        LOG_E("[%s,%d] zt_io_write32 failed", __func__, __LINE__);
        goto exit;
    }

    mailbox_reg_addr += MAILBOX_WORD_LEN;
    ret = zt_io_write32(nic_info, mailbox_reg_addr, recv_len);
    if (ZT_RETURN_FAIL == ret)
    {
        LOG_E("[%s,%d] zt_io_write32 failed", __func__, __LINE__);
        goto exit;
    }

    mailbox_reg_addr += MAILBOX_WORD_LEN;

    while ((send_len--) && send_buf)
    {
        ret = zt_io_write32(nic_info, mailbox_reg_addr, *send_buf++);
        if (ZT_RETURN_FAIL == ret)
        {
            LOG_E("[%s,%d] zt_io_write32 failed", __func__, __LINE__);
            goto exit;
        }
        mailbox_reg_addr += MAILBOX_WORD_LEN;
    }

    ret = zt_mcu_cmd_get_status(nic_info, cmd);
    if (ZT_RETURN_FAIL == ret)
    {
        LOG_E("mcu_cmd_get_status failed, check mcu feedback");
        goto exit;
    }
    else if (ZT_RETURN_REMOVED_FAIL == ret)
    {
        LOG_W("[%s,%d] driver or device is removed. cmd:0x%08x,%s", __func__, __LINE__,
              cmd, cmd_to_str(cmd));
        goto exit;
    }

    mailbox_reg_addr = MAILBOX_ARG_START;
    if (ret == 0)
    {
        while ((recv_len--) && recv_buf)
        {
            *recv_buf++ = zt_io_read32(nic_info, mailbox_reg_addr, NULL);
            mailbox_reg_addr += MAILBOX_WORD_LEN;
        }
    }

    ret = ZT_RETURN_OK;

exit:
    nic_mcu_hw_access_unlock(nic_info);

    return ret;
}


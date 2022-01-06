/*
 * proc.c
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

#include "ndev_linux.h"
#include "proc.h"
#include "common.h"
#include "hif.h"

#define __user

static zt_s32 zt_get_version_info(struct seq_file *m, void *v)
{
#ifdef COMPILE_TIME
    zt_print_seq(m, "Driver Ver:%s, Compile time:%s\n", ZT_VERSION, COMPILE_TIME);
#else
    zt_print_seq(m, "Driver Ver:%s\n", ZT_VERSION);
#endif
    return 0;
}

static zt_s32 zt_get_wlan_mgmt_info(struct seq_file *m, void *v)
{
    nic_info_st *pnic_info;
    hif_node_st *hif_info  = m->private;
    zt_wlan_mgmt_info_t *pwlan_mgmt_info;

    if (NULL == hif_info)
    {
        LOG_W("[%s] hif_info is null", __func__);
        return -1;
    }

    pnic_info = hif_info->nic_info[0];
    if (NULL == pnic_info)
    {
        LOG_W("[%s] pnic_info is null", __func__);
        return -1;
    }

    pwlan_mgmt_info = pnic_info->wlan_mgmt_info;
    /* ap message free queue */
    if (NULL == pwlan_mgmt_info)
    {
        LOG_W("[%s] pwlan_mgmt_info is null", __func__);
        return -1;
    }

    {
        zt_wlan_mgmt_scan_que_t *pscan_que = &pwlan_mgmt_info->scan_que;
        zt_print_seq(m, "pscan_que->free.count=%d\n",
                     zt_que_count(&pscan_que->free));
        zt_print_seq(m, "pscan_que->ready.count=%d\n",
                     zt_que_count(&pscan_que->ready));
        zt_print_seq(m, "pscan_que->read_cnt=%d\n", pscan_que->read_cnt);
        if (0)
        {
            zt_wlan_mgmt_scan_que_node_t *pscan_que_node;
            zt_wlan_mgmt_scan_que_for_rst_e scan_que_for_rst;
            zt_print_seq(m, "-------------------------\n");
            zt_wlan_mgmt_scan_que_for_begin(pnic_info, pscan_que_node)
            {
                zt_print_seq(m, "sig_str: %d, ssid: %s\n",
                             pscan_que_node->signal_strength,
                             pscan_que_node->ssid.data);
            }
            zt_wlan_mgmt_scan_que_for_end(scan_que_for_rst);
        }
    }

    return 0;
}


static zt_s32 zt_get_mlme_info(struct seq_file *m, void *v)
{
    nic_info_st *pnic_info;
    hif_node_st *hif_info = m->private;
    mlme_info_t *pmlme_info;

    if (NULL == hif_info)
    {
        LOG_W("[%s] hif_info is null", __func__);
        return -1;
    }

    pnic_info = hif_info->nic_info[0];
    if (NULL == pnic_info)
    {
        LOG_W("[%s] pnic_info is null", __func__);
        return -1;
    }

    pmlme_info = pnic_info->mlme_info;
    /* ap message free queue */
    if (NULL == pmlme_info)
    {
        LOG_W("[%s] pnic_info->mlme_info is null", __func__);
        return -1;
    }

    {
        zt_print_seq(m, "pmlme_info->link_info.busy_traffic=%d\n",
                     pmlme_info->link_info.busy_traffic);
    }

    return 0;
}


static zt_s32 zt_get_rx_info(struct seq_file *m, void *v)
{
    hif_node_st *hif_info           = m->private;
    wdn_net_info_st *wdn_net_info   = NULL;
    data_queue_node_st *data_node   = NULL;
    zt_s32 i                        = 0;
    if (NULL == hif_info)
    {
        LOG_E("[%s] hif_info is null", __func__);
        return -1;
    }


    /*hif debug info*/
    zt_print_seq(m, "node_id:%d\n", hif_info->node_id);
    zt_print_seq(m, "hif_type:%d\n", hif_info->hif_type);
    zt_print_seq(m, "rx_queue_cnt:%lld\n", hif_info->trx_pipe.rx_queue_cnt);
    zt_print_seq(m, "free rx data queue node num:%d\n",
                 hif_info->trx_pipe.free_rx_queue.cnt);

    for (i = 0; i < ZT_RX_MAX_DATA_QUEUE_NODE_NUM; i++)
    {
        data_node = hif_info->trx_pipe.all_rx_queue + i;
        if (0 != data_node->state)
        {
            zt_print_seq(m, "[%d] state:%d, pg_num:%d,agg_num:%d\n",
                         data_node->node_id, data_node->state,
                         data_node->pg_num, data_node->agg_num);
        }
    }

    zt_print_seq(m, "rx skb queue_len:%d\n",
                 skb_queue_len(&hif_info->trx_pipe.rx_queue));
    zt_print_seq(m, "free rx skb queue_len:%d\n",
                 skb_queue_len(&hif_info->trx_pipe.free_rx_queue_skb));

    if (NULL != wdn_net_info)
    {
        zt_s32 tid = 0;
        if (wdn_net_info->ba_ctl != NULL)
        {
            for (tid = 0; tid < TID_NUM; tid++)
            {
                recv_ba_ctrl_st *ba_ctl = &wdn_net_info->ba_ctl[tid];
                if (NULL != ba_ctl && zt_true == ba_ctl->enable)
                {
                    zt_print_seq(m, "[%d] rx reorder drop:%lld\n",
                                 tid, ba_ctl->drop_pkts);
                    zt_print_seq(m, "[%d] timeout_cnt:%u\n",
                                 tid, ba_ctl->timeout_cnt);
                }
            }
        }
    }

    return 0;
}

static ssize_t zt_set_tx_info(struct file *file, const char __user *buffer,
                              size_t count, loff_t *pos, void *data)
{
#if LINUX_VERSION_CODE == KERNEL_VERSION(4, 4, 13)
#define MAX_NIC 5
    hif_node_st *hif_info = data;
    nic_info_st *pnic_info = NULL;
    char tmp[32];
    zt_s32 ndev_id;
    zt_s32 set_id;
    zt_s32 val;
    if (count < 1)
    {
        return -EINVAL;
    }

    if (NULL == hif_info)
    {
        return -EINVAL;
    }
    else
    {
        LOG_I("node:%d,type:%d", hif_info->node_id, hif_info->hif_type);
    }

    if (count > sizeof(tmp))
    {
        LOG_E("input param len is out of range");
        return -EFAULT;
    }

    if (buffer && !copy_from_user(tmp, buffer, count))
    {
        zt_s32 num = sscanf(tmp, "%d %d %d", &ndev_id, &set_id, &val);
        if (num == 3)
        {
            LOG_I("ndev_id:%d, set_id:%d, val:%d\n", ndev_id, set_id, val);
            if (ndev_id < MAX_NIC)
            {
                pnic_info = hif_info->nic_info[ndev_id];
                if (pnic_info)
                {
                    if (zt_wdn_get_cnt(pnic_info)) // assosicated
                    {
                        zt_list_t *pos = NULL;
                        zt_list_t *next = NULL;
                        wdn_node_st *tmp_node = NULL;
                        wdn_list *wdn = (wdn_list *)pnic_info->wdn;
                        if (0 == set_id) //tx_rate
                        {
                            zt_list_for_each_safe(pos, next, &wdn->head)
                            {
                                tmp_node = zt_list_entry(pos, wdn_node_st, list);
                                if (tmp_node)
                                {
                                    tmp_node->info.tx_rate = val;
                                    LOG_I("wdn_id:%d, tx_rate:%d",
                                          tmp_node->info.wdn_id, val);
                                }
                                tmp_node = NULL;
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        return -EFAULT;
    }
#endif
    return count;
}

static zt_s32 zt_get_tx_info(struct seq_file *m, void *v)
{
    hif_node_st *hif_info           = m->private;
    nic_info_st *pnic_info          = NULL;
    tx_info_st *tx_info             = NULL;
    data_queue_node_st *data_node   = NULL;
    zt_s32 i                        = 0;
    if (NULL == hif_info)
    {
        LOG_E("[%s] hif_info is null", __func__);
        return -1;
    }


    /*hif debug info*/
    zt_print_seq(m, "node_id:%d\n", hif_info->node_id);
    zt_print_seq(m, "hif_type:%d\n", hif_info->hif_type);
    zt_print_seq(m, "tx_queue_cnt:%lld\n", hif_info->trx_pipe.tx_queue_cnt);
    zt_print_seq(m, "free tx data queue node num:%d\n",
                 hif_info->trx_pipe.free_tx_queue.cnt);
    zt_print_seq(m, "tx data queue node num:%d\n",
                 hif_info->trx_pipe.tx_queue.cnt);

    for (i = 0; i < ZT_TX_MAX_DATA_QUEUE_NODE_NUM; i++)
    {
        data_node = hif_info->trx_pipe.all_tx_queue + i;
        if ((TX_STATE_COMPETE != data_node->state) &&
                (TX_STATE_IDL != data_node->state))
        {
            zt_print_seq(m, "[%d] state:%d, pg_num:%d,agg_num:%d, addr:0x%x\n",
                         data_node->node_id, data_node->state, data_node->pg_num,
                         data_node->agg_num, data_node->addr);
        }
    }

    if (HIF_SDIO == hif_info->hif_type)
    {
        hif_sdio_st *sd = &hif_info->u.sdio;

        zt_print_seq(m, "tx_fifo_ppg_num    :%d\n", sd->tx_fifo_ppg_num);
        zt_print_seq(m, "tx_fifo_hpg_num    :%d\n", sd->tx_fifo_hpg_num);
        zt_print_seq(m, "tx_fifo_lpg_num    :%d\n", sd->tx_fifo_lpg_num);
    }

    pnic_info = hif_info->nic_info[0];
    if (NULL == pnic_info)
    {

        return 0;
    }

    tx_info = pnic_info->tx_info;
    zt_print_seq(m, "free tx frame num:%d,free_xmitbuf_cnt:%d\n",
                 tx_info->free_xmitframe_cnt, tx_info->free_xmitbuf_cnt);
    zt_print_seq(m, "data_queue_check:%d",
                 zt_io_write_data_queue_check(pnic_info));
    zt_print_seq(m, "check_tx_buff:%d", zt_mcu_check_tx_buff(pnic_info));
    return 0;
}


static zt_s32 zt_get_ars_fw_dbg_info(struct seq_file *m, void *v)
{
    hif_node_st *hif_info = m->private;
    nic_info_st *pnic_info = NULL;
    ars_fw_dbg_info_st info;
    if (NULL == hif_info)
    {
        LOG_E("[%s] hif_info is null", __func__);
        return -1;
    }


    /*hif debug info*/
    zt_print_seq(m, "node_id:%d\n", hif_info->node_id);
    zt_print_seq(m, "hif_type:%d\n", hif_info->hif_type);

    pnic_info = hif_info->nic_info[0];
    if (NULL == pnic_info)
    {
        LOG_E("[%s] pnic_info is null", __func__);
        return -2;
    }

    zt_mcu_ars_get_dbg_info(pnic_info, (zt_u32 *)&info, sizeof(info));
    zt_print_seq(m, "Parity Fail:%d\n", info.fas.parity_failed_cnt);
    zt_print_seq(m, "Rate Illegal:%d\n", info.fas.rate_illegal_cnt);
    zt_print_seq(m, "Crc8 fail:%d\n", info.fas.crc8_failed_cnt);
    zt_print_seq(m, "Mcs fail:%d\n", info.fas.mcs_failed_cnt);
    zt_print_seq(m, "Ofdm fail:%d\n", info.fas.ofdm_failed_cnt);
    zt_print_seq(m, "Ofdm fail pre:%d\n", info.fas.ofdm_pre_failed_cnt);
    zt_print_seq(m, "Cck fail:%d\n", info.fas.cck_failed_cnt);
    zt_print_seq(m, "all fail:%d\n", info.fas.all_cnt);
    zt_print_seq(m, "Fast Fsync:%d\n", info.fas.fast_fsync_cnt);
    zt_print_seq(m, "SB_Search fail:%d\n", info.fas.sb_search_failed_cnt);
    zt_print_seq(m, "OFDM CCA:%d\n", info.fas.ofdm_cca_cnt);
    zt_print_seq(m, "CCK CCA:%d\n", info.fas.cck_cca_cnt);
    zt_print_seq(m, "CCA all:%d\n", info.fas.cca_all_cnt);
    zt_print_seq(m, "BW_USC:%d\n", info.fas.bw_usc_cnt);
    zt_print_seq(m, "BW_LSC:%d\n", info.fas.bw_lsc_cnt);

    zt_print_seq(m, "noisy_decision:%d\n", info.noisy_decision);
    zt_print_seq(m, "tddi_min:%d\n", info.tddi_min);
    zt_print_seq(m, "pwdb:%d\n", info.pwdb);
    zt_print_seq(m, "change_state:%d\n", info.change_state);
    zt_print_seq(m, "pt_scroe:%d\n", info.pt_scroe);
    zt_print_seq(m, "cur_igi:%d\n", info.cur_igi);
    zt_print_seq(m, "igi_dynamic_min:%d\n", info.igi_dynamic_min);
    zt_print_seq(m, "igi_target:%d\n", info.igi_target);
    zt_print_seq(m, "rssi_level:%d\n", info.rssi_level);
    zt_print_seq(m, "crsytal_cap:%d\n", info.crsytal_cap);
    zt_print_seq(m, "cfo_avg_pre:%d\n", info.cfo_avg_pre);
    zt_print_seq(m, "thermal_val:%d\n", info.thermal_val);
    zt_print_seq(m, "thermal_lck:%d\n", info.thermal_lck);
    zt_print_seq(m, "thermal_iqk:%d\n", info.thermal_iqk);
    zt_print_seq(m, "dpk_thermal:%d\n", info.dpk_thermal);
    zt_print_seq(m, "sq:0x%x\n", info.seq);
    zt_print_seq(m, "support_ability:0x%x\n", info.support_ability);
    zt_print_seq(m, "proc_flag:%d\n", info.proc_flag);
    zt_print_seq(m, "NHM_cnt_0:%d\n", info.NHM_cnt_0);
    zt_print_seq(m, "ForcePowerTrainingState:%d\n",
                 info.force_power_trainging_state);
    zt_print_seq(m, "end_flag:0x%x\n", info.end_flag);
    return 0;
}

static ssize_t zt_set_ars_fw_dbg_info(struct file *file,
                                      const char __user *buffer,
                                      size_t count, loff_t *pos, void *data)
{
#if LINUX_VERSION_CODE == KERNEL_VERSION(4, 4, 13) || \
    LINUX_VERSION_CODE == KERNEL_VERSION(4, 15, 18)
    hif_node_st *hif_info = data;
    nic_info_st *pnic_info = NULL;
    char tmp[32];
    zt_s32 ndev_id;
    zt_s32 set_id;
    zt_s32 val;
    ars_fw_set_msg_st *info = NULL;
    zt_u32 arg[20];
    static zt_u32 ars_seq_num = 0;
    if (NULL == hif_info)
    {
        return -EINVAL;
    }
    else
    {
        LOG_I("[%d] node:%d,type:%d", __LINE__, hif_info->node_id,
              hif_info->hif_type);
    }

    if (count > sizeof(tmp))
    {
        LOG_E("input param len is out of range");
        return -EFAULT;
    }

    if (buffer && !copy_from_user(tmp, buffer, count))
    {
        zt_s32 num = sscanf(tmp, "%d %d %d", &ndev_id, &set_id, &val);
        if (num == 3)
        {
            LOG_I("[%d] ndev_id:%d set_id:%d, val:%d\n", __LINE__,
                  ndev_id, set_id, val);
        }
        pnic_info = hif_info->nic_info[ndev_id];
        if (NULL == pnic_info)
        {
            LOG_E("ndev_id is error");
            return -EFAULT;
        }

        info = (ars_fw_set_msg_st *)&arg[0];
        switch (set_id)
        {
            case 0://ars switch open/close
            {
                zt_mcu_ars_switch(pnic_info, val);
                break;
            }
            case 1: //set support_ability
            {
                if (-1 == val)
                {
                    info->value = 0 | ZT_BIT(3);
                }
                else if (0 <= val)
                {
                    info->value |= ZT_BIT(val);
                }


                break;
            }
            case 2: //ForcePowerTrainingState
            {
                info->value = val;
            }
        }

        if (0 != set_id)
        {
            info->set_id = ZT_BIT(set_id);
            info->seq = ars_seq_num++;
            LOG_I("set_id:%d,seq:%d", info->set_id, info->seq);
            zt_mcu_ars_set_dbg_info(pnic_info, (zt_u32 *)info,
                                    sizeof(ars_fw_set_msg_st));
        }

    }
#endif

    return count;

}


#ifdef CFG_ENABLE_AP_MODE
static zt_s32 zt_get_ap_info(struct seq_file *m, void *v)
{
    hif_node_st *hif_info  = m->private;
    nic_info_st *pnic_info = NULL;
    zt_wlan_mgmt_info_t *pwlan_info;
    zt_wlan_network_t *pcur_network;
    wdn_list *pwdn;
    wdn_net_info_st *pwdn_info;
    zt_list_t *pos, *pos_next;
    sec_info_st *psec_info = NULL;
    zt_s32 i = 0;

    if (NULL == hif_info)
    {
        LOG_E("[%s] hif_info is null", __func__);
        return -1;
    }

    for (i = 0; i < hif_info->nic_number; i++)
    {
        pnic_info = hif_info->nic_info[i];
        if (NULL == pnic_info)
        {
            continue;
        }

        zt_print_seq(m, "--------------nic[%d] ----------\n ", i);

        /* ap message free queue */
        pwlan_info = pnic_info->wlan_mgmt_info;
        if (pwlan_info)
        {
            pcur_network = &pwlan_info->cur_network;
            zt_print_seq(m, "ap_msg_free[ZT_AP_MSG_TAG_AUTH_FRAME].count=%d\n",
                         pcur_network->ap_msg_free[ZT_AP_MSG_TAG_AUTH_FRAME].cnt);
            zt_print_seq(m, "ap_msg_free[ZT_AP_MSG_TAG_ASSOC_REQ_FRAME].count=%d\n",
                         pcur_network->ap_msg_free[ZT_AP_MSG_TAG_ASSOC_REQ_FRAME].cnt);
            zt_print_seq(m, "pcur_network->ap_tid=%08lx\n",
                         (long)pcur_network->ap_tid);
            zt_print_seq(m, "pcur_network->channel=%d\n", pcur_network->channel);
        }

        psec_info = pnic_info->sec_info;
        if (psec_info)
        {
            zt_print_seq(m, "psec_info->dot11AuthAlgrthm=%d\n",
                         psec_info->dot11AuthAlgrthm);
        }

        /* wdn message queue */
        pwdn = pnic_info->wdn;
        pwdn_info = pnic_info->wdn;
        if (pwdn)
        {
            zt_print_seq(m, "\npwdn->cnt=%d", pwdn->cnt);
            zt_print_seq(m, "\npwdn->id_bitmap=0x%x\n", pwdn->id_bitmap);
            zt_list_for_each_safe(pos, pos_next, &pwdn->head)
            {
                pwdn_info = &zt_list_entry(pos, wdn_node_st, list)->info;
                zt_print_seq(m, "pwdn_info->wdn_id=%d\n", pwdn_info->wdn_id);
                zt_print_seq(m, "         ->channel=%d\n", pwdn_info->channel);
                zt_print_seq(m, "         ->mac="ZT_MAC_FMT"\n",
                             ZT_MAC_ARG(pwdn_info->mac));
                zt_print_seq(m, "         ->ieee8021x_blocked=%d\n",
                             pwdn_info->ieee8021x_blocked);
                zt_print_seq(m, "         ->dot118021XPrivacy=%d\n",
                             pwdn_info->dot118021XPrivacy);
                zt_print_seq(m, "         ->ap_msg.count=%d\n",
                             pwdn_info->ap_msg.cnt);
                zt_print_seq(m, "         ->ap_msg.rx_pkt_stat=%d\n",
                             pwdn_info->rx_pkt_stat);
            }
        }
    }
    return 0;
}


#endif
static zt_s32 zt_get_sta_info(struct seq_file *m, void *v)
{
    nic_info_st *pnic_info = NULL;
    hif_node_st *hif_info  = m->private;
    wdn_list *pwdn;
    wdn_net_info_st *pwdn_info;
    zt_list_t *pos, *pos_next;
    sec_info_st *psec_info = NULL;

    if (NULL == hif_info)
    {
        LOG_E("[%s] hif_info is null", __func__);
        return -1;
    }

    pnic_info = hif_info->nic_info[0];
    if (NULL == pnic_info)
    {
        LOG_E("[%s] pnic_info is null", __func__);
        return -1;
    }

    psec_info = pnic_info->sec_info;
    /* ap message free queue */
    if (psec_info)
    {
        zt_print_seq(m, "psec_info->dot11AuthAlgrthm=%d\n",
                     psec_info->dot11AuthAlgrthm);
    }

    /* wdn message queue */
    pwdn = pnic_info->wdn;
    pwdn_info = pnic_info->wdn;
    if (pwdn)
    {
        zt_print_seq(m, "\npwdn->cnt=%d", pwdn->cnt);
        zt_print_seq(m, "\npwdn->id_bitmap=0x%x\n", pwdn->id_bitmap);
        zt_list_for_each_safe(pos, pos_next, &pwdn->head)
        {
            pwdn_info = &zt_list_entry(pos, wdn_node_st, list)->info;
            zt_print_seq(m, "pwdn_info->wdn_id=%d\n", pwdn_info->wdn_id);
            zt_print_seq(m, "         ->mac="ZT_MAC_FMT"\n",
                         ZT_MAC_ARG(pwdn_info->mac));
            zt_print_seq(m, "         ->ieee8021x_blocked=%d\n",
                         pwdn_info->ieee8021x_blocked);
            zt_print_seq(m, "         ->dot118021XPrivacy=%d\n",
                         pwdn_info->dot118021XPrivacy);
        }
    }

    return 0;
}

static zt_s32 zt_get_hif_info(struct seq_file *m, void *v)
{
    hif_node_st *hif_info           = m->private;
    zt_s32 i = 0;
    data_queue_node_st *data_node   = NULL;

    if (NULL == hif_info)
    {
        LOG_E("[%s] hif_info is null", __func__);
        return -1;
    }

    /*hif debug info*/
    zt_print_seq(m, "node_id : %d, nic_num:%d\n", hif_info->node_id,
                 hif_info->nic_number);
    zt_print_seq(m, "hif_type: %s\n",
                 hif_info->hif_type == 1 ? "HIF_USB" : "HIF_SDIO");

    /*hif--rx info*/
    zt_print_seq(m, "[rx] all  queue cnt:%lld\n",
                 hif_info->trx_pipe.rx_queue_cnt);
    zt_print_seq(m, "[rx] free queue node num:%d\n",
                 hif_info->trx_pipe.free_rx_queue.cnt);

    for (i = 0; i < ZT_RX_MAX_DATA_QUEUE_NODE_NUM; i++)
    {
        data_node = hif_info->trx_pipe.all_rx_queue + i;
        if (0 != data_node->state)
        {
            zt_print_seq(m, "[rx] qnode(%d) state:%d, pg_num:%d,agg_num:%d\n",
                         data_node->node_id, data_node->state,
                         data_node->pg_num, data_node->agg_num);
        }
    }

    /*hif--tx info*/
    zt_print_seq(m, "[tx] all queue cnt:%lld\n", hif_info->trx_pipe.tx_queue_cnt);
    zt_print_seq(m, "[tx] free  tx data queue node num:%d\n",
                 hif_info->trx_pipe.free_tx_queue.cnt);
    zt_print_seq(m, "[tx] using tx data queue node num:%d\n",
                 hif_info->trx_pipe.tx_queue.cnt);
    for (i = 0; i < ZT_TX_MAX_DATA_QUEUE_NODE_NUM; i++)
    {
        data_node = hif_info->trx_pipe.all_tx_queue + i;
        if ((TX_STATE_COMPETE != data_node->state) &&
                (TX_STATE_IDL != data_node->state))
        {
            zt_print_seq(m, "[tx] qnode(%d) state:%d, pg_num:%d,agg_num:%d, addr:0x%x\n",
                         data_node->node_id, data_node->state,
                         data_node->pg_num, data_node->agg_num, data_node->addr);
        }
    }
    if (HIF_SDIO == hif_info->hif_type)
    {
        hif_sdio_st *sd = &hif_info->u.sdio;

        zt_print_seq(m, "[tx] fifo_ppg_num    :%d\n", sd->tx_fifo_ppg_num);
        zt_print_seq(m, "[tx] fifo_hpg_num    :%d\n", sd->tx_fifo_hpg_num);
        zt_print_seq(m, "[tx] fifo_lpg_num    :%d\n", sd->tx_fifo_lpg_num);
        zt_print_seq(m, "[tx] tx_state:%d\n", sd->tx_state);
    }

    /*register info*/
    {
        nic_info_st *pnic_info = hif_info->nic_info[0];
        if (NULL == pnic_info)
        {
            LOG_E("[%s] pnic_info is null", __func__);
            return -1;
        }
    }
    return 0;
}

const struct zt_proc_handle proc_hdls[] =
{
    zt_register_proc_interface("version",   zt_get_version_info,    NULL),
    zt_register_proc_interface("tx",        zt_get_tx_info,         zt_set_tx_info),
    zt_register_proc_interface("rx",        zt_get_rx_info,         NULL),

    zt_register_proc_interface("ars",       zt_get_ars_fw_dbg_info, zt_set_ars_fw_dbg_info),
#ifdef CFG_ENABLE_AP_MODE
    zt_register_proc_interface("ap",        zt_get_ap_info,         NULL),
#endif
    zt_register_proc_interface("sta",       zt_get_sta_info,        NULL),
    zt_register_proc_interface("hif",       zt_get_hif_info,        NULL),
    zt_register_proc_interface("wlan_mgmt", zt_get_wlan_mgmt_info,  NULL),
    zt_register_proc_interface("mlme",      zt_get_mlme_info,       NULL),
};
const zt_s32 zt_proc_hdls_num = sizeof(proc_hdls) / sizeof(
                                    struct zt_proc_handle);




inline struct proc_dir_entry *zt_proc_create_dir(const zt_s8 *name,
        struct proc_dir_entry *parents, void *data)
{
    struct proc_dir_entry *entry;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
#if 1
    entry = proc_mkdir_data(name, S_IRUGO | S_IXUGO, parents, data);
#else
    entry = proc_mkdir(name, parents);
    if (!entry)
    {
        LOG_E("[proc_mkdir]1 error!\n");
    }
#endif
#else
    /* entry = proc_mkdir_mode(name, S_IRUGO|S_IXUGO, parent); */
    entry = proc_mkdir(name, parents);
    if (!entry)
    {
        LOG_E("[proc_mkdir]2 error!\n");
    }
    if (entry)
    {
        entry->data = data;
    }
#endif

    return entry;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 5, 0)
inline struct proc_dir_entry *zt_proc_create_entry(const zt_s8 *name,
        struct proc_dir_entry *parents,
        const struct proc_ops *fops, void *data)
#else
inline struct proc_dir_entry *zt_proc_create_entry(const zt_s8 *name,
        struct proc_dir_entry *parents,
        const struct file_operations *fops, void *data)
#endif
{
    struct proc_dir_entry *entry;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26))
    entry = proc_create_data(name,  S_IFREG | S_IRUGO | S_IWUGO, parents, fops,
                             data);
#else
    entry = create_proc_entry(name, S_IFREG | S_IRUGO | S_IWUGO, parents);
    if (entry)
    {
        entry->data = data;
        entry->proc_fops = fops;
    }
#endif

    return entry;
}

static SSIZE_T zt_proc_write(struct file *file, const char __user *buffer,
                             SIZE_T count, loff_t *pos)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 9, 1))
    return 0;
#else

    ssize_t index = (ssize_t)PDE_DATA(file_inode(file));
    const struct zt_proc_handle *hdl = proc_hdls + index;
    ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *,
                     void *) = hdl->write;

    if (write)
    {
        return write(file, buffer, count, pos,
                     ((struct seq_file *)file->private_data)->private);
    }

    return -EROFS;
#endif
}

static zt_s32 zt_proc_open(struct inode *inode, struct file *file)
{
    ssize_t index = (ssize_t)PDE_DATA(inode);
    const struct zt_proc_handle *hdl = proc_hdls + index;
    void *private = proc_get_parent_data(inode);

    zt_s32(*show)(struct seq_file *, void *) = hdl->show ? hdl->show : 0;

    return single_open(file, show, private);

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
static const struct proc_ops zt_proc_fops =
{
    //.owner = THIS_MODULE,
    .proc_open = zt_proc_open,
    .proc_read = seq_read,
    .proc_write = zt_proc_write,
    .proc_lseek = default_llseek,
    .proc_release = single_release,
};
#else
static const struct file_operations zt_proc_fops =
{
    .owner = THIS_MODULE,
    .open = zt_proc_open,
    .read = seq_read,
    .write = zt_proc_write,
    .llseek = seq_lseek,
    .release = single_release,
};
#endif
zt_s32 zt_proc_init(void *hif_info)
{
    zt_s32 ret = zt_false;
    SSIZE_T p;
    hif_node_st *hif_node = (hif_node_st *)hif_info;
    zt_proc_st   *proc_info      = NULL;
    struct proc_dir_entry *entry = NULL;

    proc_info   = zt_kzalloc(sizeof(zt_proc_st));
    if (NULL == proc_info)
    {
        LOG_E("[%s] malloc proc_info failed", __func__);
        return ZT_RETURN_FAIL;
    }


    LOG_D("[%s] start\n", __func__);

    if (hif_node->hif_type == HIF_USB)
    {

        zt_sprintf(proc_info->proc_name, "wlan%d_u%d", hif_node->node_id,
                   hif_node->u.usb.usb_id);
    }
    else
    {
        zt_sprintf(proc_info->proc_name, "wlan%d_s%d", hif_node->node_id,
                   hif_node->u.sdio.sdio_id);
    }

    proc_info->proc_root = zt_proc_create_dir(proc_info->proc_name, zt_proc_net,
                           hif_node);
    if (NULL == proc_info->proc_root)
    {
        LOG_E("[%s]proc dir create error", __func__);
    }

    for (p = 0; p < zt_proc_hdls_num; p++)
    {

        entry = zt_proc_create_entry(proc_hdls[p].name, proc_info->proc_root,
                                     &zt_proc_fops, (void *)p);
        if (!entry)
        {
            LOG_E("[%s]proc entry create error", __func__);
        }
    }

    proc_info->hif_info = hif_info;
    hif_node->proc_info = proc_info;


    return ret;

}
void zt_proc_term(void *hif_info)
{
    zt_s32 i;
    hif_node_st *hif_node        = hif_info;
    zt_proc_st   *proc_info      = hif_node->proc_info;

    if (proc_info == NULL)
    {
        return;
    }

    if (proc_info->proc_root == NULL)
    {
        return;
    }

    for (i = 0; i < zt_proc_hdls_num; i++)
    {
        remove_proc_entry(proc_hdls[i].name, proc_info->proc_root);
    }

    remove_proc_entry(proc_info->proc_name, zt_proc_net);
    proc_info->proc_root = NULL;

    zt_kfree(proc_info);
    proc_info = NULL;

}


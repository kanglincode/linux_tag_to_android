/*
 * rx.c
 *
 * used for rx frame handle
 *
 * Author: renhaibo
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
#include "queue.h"

#define BA_REORDER_QUEUE_NUM (64)

#define MMPDU_SIZE              2304
#define MAX_MGNT_HDR_LEN        28
#define MIN_MGNT_HDR_LEN        24
#define MAC_HEADER_OFFSET       56
#define DATA_FRAME_HDR_SHORT    24
#define ADDRESS4_LEN            6
#define QOS_CONTRL_LEN          2
#define HT_CONTRL_LEN           4

zt_inline zt_u8 *pkt_push(prx_pkt_t prx_pkt, zt_s32 size)
{
    if (prx_pkt->pdata - size < prx_pkt->phead)
    {
        return NULL;
    }

    prx_pkt->pdata -= size;
    prx_pkt->len += size;

    return prx_pkt->pdata;
}

zt_inline static zt_u8 *pkt_put(prx_pkt_t prx_pkt, zt_s32 size)
{
    zt_u8 *ptmp;

    if (prx_pkt->ptail + size > prx_pkt->pend)
    {
        return NULL;
    }
    ptmp = prx_pkt->ptail;

    prx_pkt->ptail += size;
    prx_pkt->len += size;

    return ptmp;
}
zt_inline static void pkt_reserve(prx_pkt_t prx_pkt, zt_s32 size)
{
    prx_pkt->pdata += size;
    prx_pkt->ptail += size;
}

zt_inline static void free_rx_pkt(prx_pkt_t prx_pkt, zt_bool bfreeSkb)
{
    prx_info_t prx_info = ((nic_info_st *)((prx_pkt_t)(
            prx_pkt))->p_nic_info)->rx_info;
    queue_insert_tail(&prx_info->free_rx_pkt_list, &prx_pkt->entry);
}

static void free_rx_queue(p_que_t prx_q, zt_bool bfreeSkb)
{
    p_que_entry_t p_entry;
    prx_pkt_t prx_pkt;

    while (queue_is_not_empty(prx_q))
    {
        queue_remove_head(prx_q, p_entry, p_que_entry_t);
        if (p_entry == NULL)
        {
            break;
        }
        prx_pkt = (prx_pkt_t)p_entry;
        free_rx_pkt(prx_pkt, bfreeSkb);
    }
}

void set_encrypt_algo_num(prx_pkt_t ppkt, wdn_net_info_st *wdn_net_info)
{
    nic_info_st *pnic_info;
    sec_info_st *psec_info;
    zt_bool bmcast = IS_MCAST(ppkt->pkt_info.rx_addr);

    pnic_info = (nic_info_st *)ppkt->p_nic_info;
    psec_info = (sec_info_st *)pnic_info->sec_info;

    if (!GetPrivacy(ppkt->pdata))
    {
        ppkt->pkt_info.encrypt_algo = _NO_PRIVACY_;
        return ;
    }

    if (psec_info->dot11AuthAlgrthm == dot11AuthAlgrthm_8021X)
    {
        ppkt->pkt_info.encrypt_algo =
            bmcast ? psec_info->dot118021XGrpPrivacy : wdn_net_info->dot118021XPrivacy;
    }
    else
    {
        ppkt->pkt_info.encrypt_algo = psec_info->dot11PrivacyAlgrthm;
    }
}

void set_iv_icv_len(prx_pkt_t ppkt)
{
    prx_pkt_info_t prx_info = &ppkt->pkt_info;

    switch (prx_info->encrypt_algo)
    {
        case _NO_PRIVACY_:
            prx_info->iv_len    = 0;
            prx_info->icv_len   = 0;
            break;
        case _WEP40_:
        case _WEP104_:
            prx_info->iv_len = 4;
            prx_info->icv_len = 4;
            break;
        case _TKIP_:
            prx_info->iv_len = 8;
            prx_info->icv_len = 4;
            break;
        case _AES_:
            prx_info->iv_len = 8;
            prx_info->icv_len = 0;
            break;
        case _SMS4_:
            prx_info->iv_len = 18;
            prx_info->icv_len = 16;
            break;
        default:
            prx_info->iv_len = 0;
            prx_info->icv_len = 0;
            break;
    }
}

zt_u8 calc_rx_rate(zt_u8 rx_rate)
{
    zt_u8 tmp_rate = 0;

    if (rx_rate < DESC_RATEMCS8)
    {
        tmp_rate = rx_rate;
    }
    else if (rx_rate >= DESC_RATEMCS8 && rx_rate <= DESC_RATEMCS15)
    {
        tmp_rate = rx_rate - 0x08;
    }
    else if (rx_rate >= DESC_RATEMCS16 && rx_rate <= DESC_RATEMCS23)
    {
        tmp_rate = rx_rate - 0x10;
    }
    else if (rx_rate >= DESC_RATEMCS24 && rx_rate <= DESC_RATEMCS31)
    {
        tmp_rate = rx_rate - 0x18;
    }

    return tmp_rate;
}



static prx_pkt_t rx_recombination(p_que_t p_defrag_que)
{
    zt_u8 order_num = 0;
    zt_u8 *pbuff;
    zt_u8 wlan_hdr_offset;
    p_que_entry_t p_entry;
    p_que_t pdefrag_que = p_defrag_que;
    prx_pkt_t ppkt_first;
    prx_pkt_t ppkt;

    ZT_ASSERT(p_defrag_que);

    /* get first defrag pkt */
    queue_remove_head(pdefrag_que, p_entry, p_que_entry_t);
    if (p_entry == NULL)
    {
        return NULL;
    }

    ppkt_first = (prx_pkt_t)p_entry;
    if (order_num != ppkt_first->pkt_info.frag_num)
    {
        free_rx_pkt(ppkt_first, zt_true);
        return NULL;
    }

    while (queue_is_not_empty(pdefrag_que))
    {
        order_num++;  /* must be 1 */

        queue_remove_head(pdefrag_que, p_entry, p_que_entry_t);
        ppkt = (prx_pkt_t)p_entry;

        if (ppkt->pkt_info.frag_num != order_num)
        {
            free_rx_pkt(ppkt, zt_true);
            return NULL;
        }

        wlan_hdr_offset = ppkt->pkt_info.wlan_hdr_len + ppkt->pkt_info.iv_len;

        pbuff = pkt_put(ppkt_first, ppkt->len);
        if (pbuff == NULL)
        {
            free_rx_pkt(ppkt, zt_true);
            return NULL;
        }

        zt_memcpy(ppkt_first->ptail, ppkt->pdata, ppkt->len);
        ppkt_first->pkt_info.icv_len = ppkt->pkt_info.icv_len;

        free_rx_pkt(ppkt, zt_true);
    }

    free_rx_queue(pdefrag_que, zt_false);
    LOG_I("[rx_recombination]  wlanhdrLen=%d iv_len:%d",
          ppkt_first->pkt_info.wlan_hdr_len, ppkt_first->pkt_info.iv_len);

    return  ppkt_first;  /* normal return */

}


static prx_pkt_t rx_defrag(prx_pkt_t ppkt)
{
    nic_info_st *pnic_info  = (nic_info_st *)ppkt->p_nic_info;
    prx_pkt_info_t prx_pkt_info = &ppkt->pkt_info;
    p_que_t pdefrag_q = NULL;
    zt_u8 mfrag;
    zt_u8 frag_num;
    prx_pkt_t p_return_pkt = NULL;
    wdn_net_info_st *pwdn;
    p_que_entry_t p_entry;
    rx_info_t *rx_info = pnic_info->rx_info;
    prx_pkt_t ppkt_defrag;

    mfrag = prx_pkt_info->more_frag;
    frag_num = prx_pkt_info->frag_num;
    pwdn = ppkt->wdn_info;

    pdefrag_q = &pwdn->defrag_q;

    queue_remove_head(&rx_info->free_rx_pkt_list, p_entry, p_que_entry_t);
    if (p_entry == NULL)
    {
        free_rx_queue(pdefrag_q, zt_true);
        return NULL;
    }

    ppkt_defrag = (prx_pkt_t)p_entry;
    zt_memcpy(ppkt_defrag, ppkt, sizeof(rx_pkt_t));
    /* not frag pkt , return it */
    if (mfrag == 0)
    {
        if (frag_num == 0)
        {
            /* not frag pkt , return it */
            p_return_pkt = ppkt;
        }
        else if (pwdn->defrag_flag == 1)
        {
            /* the last frag pkt, insert to defrag list, and then defrag to a new pkt */
            LOG_E("[defrag] insert frag:%d", frag_num);
            queue_insert_tail(pdefrag_q, &ppkt_defrag->entry);

            p_return_pkt = rx_recombination(pdefrag_q);

            pwdn->defrag_flag = 0;
        }

    }
    else if (mfrag == 1)
    {
        /* first frag pkt */
        if (frag_num == 0)
        {
            pwdn->defrag_flag = 1;

            if (queue_is_not_empty(pdefrag_q))
            {
                free_rx_queue(pdefrag_q, zt_true);
            }

            LOG_E("[defrag] insert frag:%d", frag_num);
            queue_insert_tail(pdefrag_q, &ppkt_defrag->entry);

            p_return_pkt = NULL;
        }
        else if (pwdn->defrag_flag == 1)
        {
            /* mfrag pkt but not the last one */
            LOG_E("[defrag] insert frag:%d", frag_num);
            queue_insert_tail(pdefrag_q, &ppkt_defrag->entry);

            p_return_pkt = NULL;
        }
    }

    return p_return_pkt;
}

static void rx_parse_qos_ctrl_field(prx_pkt_t prx_pkt)
{
    zt_u8 *pbuf;
    zt_u8 qos_ctrl_offset;
    prx_pkt_info_t ppkt_info = &prx_pkt->pkt_info;
    zt_u16 to_from_ds_n8 = (zt_u8)(zt_80211_hdr_ds_get(prx_pkt->pdata) >> 8);

    ppkt_info->wlan_hdr_len = DATA_FRAME_HDR_SHORT; /* 24 bytes */
    qos_ctrl_offset = DATA_FRAME_HDR_SHORT;

    if (to_from_ds_n8 == 0x03)
    {
        ppkt_info->wlan_hdr_len += ADDRESS4_LEN; /* 24 + 6 = 30 bytes */
        qos_ctrl_offset += ADDRESS4_LEN;
    }

    if (ppkt_info->qos_flag)
    {
        pbuf = prx_pkt->pdata + qos_ctrl_offset;
        ppkt_info->qos_pri = zt_80211_hdr_qos_tid_get(pbuf);
        ppkt_info->ack_policy = zt_80211_hdr_qos_ack_policy_get(pbuf);
        ppkt_info->amsdu = zt_80211_hdr_qos_amsdu_get(pbuf);
        ppkt_info->wlan_hdr_len += QOS_CONTRL_LEN ;  /* 26/32 bytes */
    }
    else
    {
        ppkt_info->qos_pri = 0;
        ppkt_info->ack_policy = 0;
        ppkt_info->amsdu = 0;
    }
}

static zt_s32 rx_parse_ht_ctrl_field(prx_pkt_t ppkt)
{
    if (zt_80211_hdr_order_get(ppkt->pdata))
    {
        ppkt->pkt_info.wlan_hdr_len += HT_CONTRL_LEN ;
    }

    return 0;
}

static zt_s32 rx_data_pkt_sta2sta(prx_pkt_t prx_pkt)
{
#ifdef CFG_ENABLE_ADHOC_MODE
    zt_bool bmcast;
    nic_info_st *nic_info = prx_pkt->p_nic_info;
    zt_u8 *da =  GetAddr1Ptr(prx_pkt->pdata);
    zt_u8 *sa =  GetAddr2Ptr(prx_pkt->pdata);
    zt_u8 *ra =  GetAddr1Ptr(prx_pkt->pdata);
    zt_u8 *ta =  GetAddr2Ptr(prx_pkt->pdata);
    zt_u8 *bssid = GetAddr3Ptr(prx_pkt->pdata);

#if 0
    LOG_D("da:"ZT_MAC_FMT, ZT_MAC_ARG(da));
    LOG_D("sa:"ZT_MAC_FMT, ZT_MAC_ARG(sa));
    LOG_D("ta :"ZT_MAC_FMT, ZT_MAC_ARG(ta));
    LOG_D("ra :"ZT_MAC_FMT, ZT_MAC_ARG(ra));
    LOG_D("bssid :"ZT_MAC_FMT, ZT_MAC_ARG(bssid));
#endif

    if (NIC_INFO_2_WORK_MODE(nic_info) != ZT_ADHOC_MODE)
    {
        LOG_E("[%s] not ADHOC mode", __func__);
        return -1;
    }

    bmcast = zt_80211_is_bcast_addr(da);
    if (bmcast == zt_false)
    {
        if (zt_80211_is_same_addr(bssid, prx_pkt->wdn_info->bssid) == zt_false)
        {
            //LOG_E("bssid is not match, dropped!! ");
            return -1;
        }


        if (zt_80211_is_same_addr(da, nic_to_local_addr(nic_info)) == zt_false)
        {
            //LOG_E("da is not match, dropped!! ");
            //LOG_I("[da]:"ZT_MAC_FMT", [ta]:"ZT_MAC_FMT, ZT_MAC_ARG(da), ZT_MAC_ARG(ta));
            return -1;
        }
    }

    /* copy ra ta */
    zt_memcpy(prx_pkt->pkt_info.dst_addr, da, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.src_addr, sa, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.bssid, bssid, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.rx_addr, ra, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.tx_addr, ta, ZT_80211_MAC_ADDR_LEN);
#endif
    return 0;
}

static zt_s32 rx_data_pkt_ap2sta(prx_pkt_t prx_pkt)
{
    zt_bool bmcast;
    nic_info_st *nic_info = prx_pkt->p_nic_info;
    zt_u8 *da =  GetAddr1Ptr(prx_pkt->pdata);
    zt_u8 *sa =  GetAddr3Ptr(prx_pkt->pdata);
    zt_u8 *ra =  GetAddr1Ptr(prx_pkt->pdata);
    zt_u8 *ta =  GetAddr2Ptr(prx_pkt->pdata);
    zt_u8 *bssid = GetAddr2Ptr(prx_pkt->pdata);

    if (NIC_INFO_2_WORK_MODE(nic_info) != ZT_INFRA_MODE)
    {
        LOG_E("[%s] not STA mode", __func__);
        return -1;
    }

    bmcast = zt_80211_is_bcast_addr(da);
    if (bmcast == zt_false)
    {
        if (zt_80211_is_same_addr(bssid, prx_pkt->wdn_info->bssid) == zt_false)
        {
            //LOG_E("bssid is not match, dropped!! ");
            return -1;
        }


        if (zt_80211_is_same_addr(da, nic_to_local_addr(nic_info)) == zt_false)
        {
            //LOG_E("da is not match, dropped!! ");
            //LOG_I("[da]:"ZT_MAC_FMT", [ta]:"ZT_MAC_FMT, ZT_MAC_ARG(da), ZT_MAC_ARG(ta));
            return -1;
        }
    }

    /* copy ra ta */
    zt_memcpy(prx_pkt->pkt_info.dst_addr, da, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.src_addr, sa, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.bssid, bssid, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.rx_addr, ra, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.tx_addr, ta, ZT_80211_MAC_ADDR_LEN);

    return 0;
}

static zt_s32 rx_data_pkt_sta2ap(prx_pkt_t prx_pkt)
{
#ifdef CFG_ENABLE_AP_MODE
    nic_info_st *nic_info = prx_pkt->p_nic_info;
    zt_u8 *da = GetAddr3Ptr(prx_pkt->pdata);
    zt_u8 *sa = GetAddr2Ptr(prx_pkt->pdata);
    zt_u8 *ra = GetAddr1Ptr(prx_pkt->pdata);
    zt_u8 *ta = GetAddr2Ptr(prx_pkt->pdata);
    zt_u8 *bssid = GetAddr1Ptr(prx_pkt->pdata);

    /* check mode */
    if (NIC_INFO_2_WORK_MODE(nic_info) != ZT_MASTER_MODE)
    {
        //LOG_E("[%s, %d]", __func__, __LINE__);
        return -1;
    }

    /* check bssid */
    if (zt_80211_is_same_addr(bssid,
                              nic_to_local_addr(prx_pkt->p_nic_info)) == zt_false)
    {
        LOG_E("in rx_data_pkt_sta2ap, bssid error");
        return -1;
    }

    /* copy address */
    zt_memcpy(prx_pkt->pkt_info.dst_addr, da, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.src_addr, sa, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.rx_addr, ra, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.tx_addr, ta, ZT_80211_MAC_ADDR_LEN);
    zt_memcpy(prx_pkt->pkt_info.bssid, bssid, ZT_80211_MAC_ADDR_LEN);
#endif
    return 0;
}



static zt_s32 rx_check_seq_ctrl(prx_pkt_t prx_pkt)
{
    zt_u8 tid;
    prx_pkt_info_t ppkt_info = &prx_pkt->pkt_info;
    zt_u16 seq_ctrl = (ppkt_info->frag_num & 0xf) | ((ppkt_info->seq_num & 0xffff)
                      << 4);


    tid = ppkt_info->qos_pri;
    if (tid > 15)
    {
        LOG_E("in seq_ctrl func, tid error:tid=%d", tid);
        return -1;
    }

    /* todo: use to filter duplicate packet. when receive the first data packet,
    the seq_ctrl_recorder[tid] value is random, and the retry value is effect */
    if (prx_pkt->wdn_info->seq_ctrl_recorder[tid] == seq_ctrl &&
            zt_80211_hdr_retry_get(prx_pkt->pdata))
    {
        //LOG_E("retry frame , drop it");
        return -1;
    }

    prx_pkt->wdn_info->seq_ctrl_recorder[tid] = seq_ctrl;
    //LOG_I("data frame  TID[%d], SeqNum[%d]", tid, ppkt_info->seq_num);

    return 0;
}


zt_s32 rx_check_data_frame_valid(prx_pkt_t prx_pkt)
{
    zt_s32 ret = 0;
    nic_info_st *nic_info = (nic_info_st *)prx_pkt->p_nic_info;

    if (NULL == nic_info)
    {
        LOG_E("%s, check NULL == nic_info", __func__);
        return -1;
    }
    if (NULL == prx_pkt->wdn_info)
    {
        //      LOG_E("for data frame , wdn should not be null");
        return -1;
    }

    switch (NIC_INFO_2_WORK_MODE(nic_info))
    {
        case ZT_INFRA_MODE :  //sta
            if (zt_80211_hdr_ds_get(prx_pkt->pdata) != ZT_80211_FCTL_FROMDS)
            {
                LOG_E("to_from_ds field error");
                ret = -1;
                break;
            }

            ret = rx_data_pkt_ap2sta(prx_pkt);
            break;

        case ZT_MASTER_MODE : // ap
            if (zt_80211_hdr_ds_get(prx_pkt->pdata) != ZT_80211_FCTL_TODS)
            {
                LOG_E("to_from_ds field error");
                ret = -1;
                break;
            }

            ret = rx_data_pkt_sta2ap(prx_pkt);
            break;
        case ZT_ADHOC_MODE :
            ret = rx_data_pkt_sta2sta(prx_pkt);
            break;
        case ZT_AUTO_MODE :
        case ZT_REPEAT_MODE :
        case ZT_SECOND_MODES :
        case ZT_MONITOR_MODE :
        case ZT_MESH_MODE :
        default:
            LOG_W("finish the rest check");
            break;
    }

    if (ret != 0)
    {
        //LOG_E("%s, check ra, ta error", __func__);
        return -1;
    }


    ret = rx_check_seq_ctrl(prx_pkt);
    if (ret != 0)
    {
        return ret;
    }

    return 0;
}



zt_s32 rx_check_mngt_frame_valid(prx_pkt_t prx_pkt)
{
    nic_info_st *nic_info = (nic_info_st *)prx_pkt->p_nic_info;
    prx_pkt_info_t ppkt_info = &prx_pkt->pkt_info;
    zt_bool bmcast;
    zt_u8 *pbuf = prx_pkt->pdata;
    zt_u8 *pra = zt_80211_hdr_addr1(pbuf);

    if (NULL == nic_info)
    {
        LOG_E("check prx_pkt->p_nic_info == NULL ");
        return -1;
    }

    switch (NIC_INFO_2_WORK_MODE(nic_info))
    {
        case ZT_INFRA_MODE :  //sta
        case ZT_ADHOC_MODE :

            if (ppkt_info->pkt_len > MMPDU_SIZE + MAX_MGNT_HDR_LEN)
            {
                LOG_E("[rx_check_mngt_frame_valid] pkt_len error:%d", ppkt_info->pkt_len);
                return -1;
            }

            bmcast = zt_80211_is_bcast_addr(zt_80211_hdr_addr1(pbuf));
            if (!zt_80211_is_bcast_addr(pra))
            {
                if (!zt_80211_is_same_addr(pra, nic_to_local_addr(nic_info)))
                {
                    return -1;
                }
            }

            zt_memcpy(ppkt_info->src_addr, zt_80211_hdr_addr2(pbuf), ZT_80211_MAC_ADDR_LEN);
            break;

        case ZT_MASTER_MODE : // ap

            break;
        case ZT_AUTO_MODE :
        case ZT_REPEAT_MODE :
        case ZT_SECOND_MODES :
        case ZT_MONITOR_MODE :
        case ZT_MESH_MODE :
        default:
            LOG_W("finish the rest check");
            break;
    }

    return 0;
}


static zt_s32 rx_process_data_frame(prx_pkt_t ppkt)
{
    zt_s32 ret = 0;
    nic_info_st *pnic_info = NULL;
    prx_pkt_info_t  prx_pkt_info = &ppkt->pkt_info;

    if (NULL == ppkt)
    {
        return -1;
    }

    pnic_info = (nic_info_st *)ppkt->p_nic_info;
    if (NULL == pnic_info)
    {
        return -1;
    }

    rx_parse_qos_ctrl_field(ppkt);
    rx_parse_ht_ctrl_field(ppkt);
    set_encrypt_algo_num(ppkt, ppkt->wdn_info);
    set_iv_icv_len(ppkt);

    /* decrypt */
    if (zt_80211_hdr_protected_get(ppkt->pdata))
    {
        ret = zt_sec_decryptor(ppkt);
        if (ret < 0)
        {
            return -1;
        }
    }

    /* defrag  */
    if ((prx_pkt_info->more_frag == 0) && (prx_pkt_info->frag_num == 0))
    {
        ; /* no defrag frame */
    }
    else
    {
        LOG_I("rx_defrag process [frag_num:%d]", prx_pkt_info->frag_num);
        ppkt = rx_defrag(ppkt);
        ret = -1; // no process , so dropped
    }

    return ret;
}

#ifdef CFG_ENABLE_MONITOR_MODE
static zt_s32 rx_set_radiotap_hdr(prx_pkt_t ppkt)
{
    struct rx_radiotap_header *prtap_hdr = NULL;
    nic_info_st *pnic_info = ppkt->p_nic_info;
    zt_wlan_mgmt_info_t *pwlan_info = pnic_info->wlan_mgmt_info;
    zt_wlan_network_t *pcur_network = &pwlan_info->cur_network;
    zt_u16 rt_len = 8;
    zt_u16 tmp_16bit = 0;
    zt_u8 hdr_buf[64] = { 0 };
    struct rx_pkt_info *pinfo = &ppkt->pkt_info;
    struct sk_buff *pskb = ppkt->pskb;
    zt_u8 *ptr = NULL;
    zt_u8 data_rate[] =
    {
        2, 4, 11, 22,
        12, 18, 24, 36, 48, 72, 93, 108,
        0, 1, 2, 3, 4, 5, 6, 7,
    };

    prtap_hdr = (struct rx_radiotap_header *)&hdr_buf[0];
    prtap_hdr->it_version = PKTHDR_RADIOTAP_VERSION;
    if (pinfo->tsfl)
    {
        zt_u64 tmp_64bit;

        prtap_hdr->it_present |= (1 << ZT_RADIOTAP_TSFT);
        tmp_64bit = zt_cpu_to_le64(pinfo->tsfl);
        zt_memcpy(&hdr_buf[rt_len], &tmp_64bit, 8);
        rt_len += 8;
    }

    prtap_hdr->it_present |= (1 << ZT_RADIOTAP_FLAGS);

    if ((pinfo->encrypt_algo == 1) || (pinfo->encrypt_algo == 5))
    {
        hdr_buf[rt_len] |= ZT_RADIOTAP_WEP;
    }

    if (pinfo->frag_num)
    {
        hdr_buf[rt_len] |= ZT_RADIOTAP_FRAG;
    }

    hdr_buf[rt_len] |= ZT_RADIOTAP_FCS;

    if (pinfo->crc_err)
    {
        hdr_buf[rt_len] |= ZT_RADIOTAP_BADFCS;
    }

    if (pinfo->sgi)
    {
        hdr_buf[rt_len] |= 0x80;
    }
    rt_len += 1;

    if (pinfo->rx_rate < 12)
    {
        prtap_hdr->it_present |= (1 << ZT_RADIOTAP_RATE);
        hdr_buf[rt_len] = data_rate[pinfo->rx_rate];
    }
    rt_len += 1;

    tmp_16bit = 0;
    prtap_hdr->it_present |= (1 << ZT_RADIOTAP_CHANNEL);
    tmp_16bit = zt_ch_2_freq(pcur_network->channel);
    zt_memcpy(&hdr_buf[rt_len], &tmp_16bit, 2);
    rt_len += 2;

    tmp_16bit = 0;
    //  if (pHalData->CurrentBandType == 0)
    tmp_16bit |= zt_cpu_to_le16(ZT_CHAN_2GHZ);

    if (pinfo->rx_rate < 12)
    {
        if (pinfo->rx_rate < 4)
        {
            tmp_16bit |= zt_cpu_to_le16(ZT_CHAN_CCK);
        }
        else
        {
            tmp_16bit |= zt_cpu_to_le16(ZT_CHAN_OFDM);
        }
    }
    else
    {
        tmp_16bit |= zt_cpu_to_le16(ZT_CHAN_DYN);
    }
    zt_memcpy(&hdr_buf[rt_len], &tmp_16bit, 2);
    rt_len += 2;

    prtap_hdr->it_present |= (1 << ZT_RADIOTAP_DBM_ANTSIGNAL);
    //  hdr_buf[rt_len] = pinfo->phy_info.RecvSignalPower;
    hdr_buf[rt_len] = 0;
    rt_len += 1;

    prtap_hdr->it_present |= (1 << ZT_RADIOTAP_ANTENNA);
    hdr_buf[rt_len] = 0;
    rt_len += 1;

    prtap_hdr->it_present |= (1 << ZT_RADIOTAP_RX_FLAGS);
    rt_len += 2;

    if (pinfo->rx_rate >= 12 && pinfo->rx_rate < 20)
    {
        prtap_hdr->it_present |= (1 << ZT_RADIOTAP_MCS);
        hdr_buf[rt_len] |= ZT_BIT(1);

        hdr_buf[rt_len] |= ZT_BIT(0);
        hdr_buf[rt_len + 1] |= (pinfo->bw & 0x03);

        hdr_buf[rt_len] |= ZT_BIT(2);
        hdr_buf[rt_len + 1] |= (pinfo->sgi & 0x01) << 2;

        hdr_buf[rt_len] |= ZT_BIT(5);
        hdr_buf[rt_len + 1] |= (pinfo->stbc & 0x03) << 5;

        rt_len += 2;

        hdr_buf[rt_len] = data_rate[pinfo->rx_rate];
        rt_len += 1;
    }

    if (skb_headroom(pskb) < rt_len)
    {
        LOG_E("headroom is too small.");
        return -1;
    }

    ptr = skb_push(pskb, rt_len);
    if (ptr)
    {
        prtap_hdr->it_len = zt_cpu_to_le16(rt_len);
        zt_memcpy(ptr, prtap_hdr, rt_len);
    }
    else
    {
        return -1;
    }

    return 0;
}

zt_s32 rx_process_monitor_frame(prx_pkt_t ppkt)
{
    zt_s32 ret = 0;
    nic_info_st *pnic_info = NULL;

    if (NULL == ppkt)
    {
        return -1;
    }

    pnic_info = (nic_info_st *)ppkt->p_nic_info;
    if (NULL == pnic_info)
    {
        return -1;
    }

    if (rx_set_radiotap_hdr(ppkt))
    {
        return -1;
    }

    return ret;
}
#endif

/**************************************** external func *******************************************/

zt_s32 zt_rx_init(nic_info_st *nic_info)
{
    zt_s32 i;
    prx_pkt_t ppkt;
    prx_info_t prx_info;
    p_que_t pfree_que;
    prx_info = zt_kzalloc(sizeof(rx_info_t));

    LOG_I("rx_init init");

    if (prx_info == NULL)
    {
        LOG_E("in rx_init, alloc rx_info buffer error");
        return -1;
    }
    nic_info->rx_info = prx_info;

    pfree_que = &prx_info->free_rx_pkt_list;

    prx_info->p_nic_info = nic_info;

    queue_initialize(pfree_que);
    queue_initialize(&prx_info->recv_rx_pkt_list);
    queue_initialize(&prx_info->rx_mgmt_frame_defrag_list);

    prx_info->prx_pkt_buf_alloc = zt_kzalloc(sizeof(rx_pkt_t) * MAX_PKT_NUM);
    if (prx_info->prx_pkt_buf_alloc == NULL)
    {
        LOG_E("prx_pkt_buf_alloc ==null");
        zt_kfree(prx_info->p_nic_info);
        return -1;
    }
    ppkt = (prx_pkt_t)prx_info->prx_pkt_buf_alloc;
    for (i = 0 ; i < MAX_PKT_NUM ; i++)
    {
        queue_insert_tail(pfree_que, &ppkt[i].entry);
    }
    zt_rx_action_ba_ctl_init(nic_info);
    return 0;
}

zt_s32 zt_rx_term(nic_info_st *nic_info)
{
    rx_info_t *rx_info = nic_info->rx_info;

    LOG_D("[zt_rx_term] start");

    if (rx_info)
    {
        zt_rx_action_ba_ctl_deinit(nic_info);
        if (rx_info->prx_pkt_buf_alloc)
        {
            zt_kfree(rx_info->prx_pkt_buf_alloc);
        }

        zt_kfree(rx_info);
        nic_info->rx_info = NULL;
    }

    LOG_D("[zt_rx_term] end");

    return 0;
}

/*
common process
include check valid, header process
*/
zt_s32 zt_rx_common_process(prx_pkt_t ppkt)
{
    zt_s32 ret = 0;
    zt_u32 frame_type;
    nic_info_st *pnic_info = ppkt->p_nic_info;
    rx_info_t *rx_info = pnic_info->rx_info;
    mlme_info_t *mlme_info = pnic_info->mlme_info;
    wdn_net_info_st *pwdn_info;

    /* retrive wdn_info */
    pwdn_info = zt_wdn_find_info(ppkt->p_nic_info, get_ta(ppkt->pdata));
    ppkt->wdn_info = pwdn_info;

    if (pwdn_info != NULL)
    {
        /* rx packet statistics used for connection alive check */
        pwdn_info->rx_pkt_stat++;
    }

#ifdef CONFIG_LPS
    if (!MacAddr_isBcst(get_da(ppkt->pdata)) && (!IS_MCAST(get_da(ppkt->pdata))))
    {
        mlme_info->link_info.num_rx_unicast_ok_in_period++;
    }
#endif

#ifdef CFG_ENABLE_MONITOR_MODE
    if (zt_local_cfg_get_work_mode(pnic_info) == ZT_MONITOR_MODE)
    {
        ret = rx_process_monitor_frame(ppkt);
        return ret;
    }
#endif

    frame_type = zt_80211_hdr_ftype_get(ppkt->pdata);
    switch (frame_type)
    {
        case ZT_80211_FTYPE_DATA :
            ret = rx_check_data_frame_valid(ppkt);
            if (ret < 0)
            {
                break;
            }

            rx_info->rx_data_pkt++;

            ret = rx_process_data_frame(ppkt);
            if (ret < 0)
            {
                rx_info->rx_drop++;
                break;
            }

            mlme_info->link_info.num_rx_ok_in_period++;
            rx_info->rx_pkts++;
            break;

        case ZT_80211_FTYPE_MGMT:

            ret = rx_check_mngt_frame_valid(ppkt);
            if (ret < 0)
            {
                break;
            }

            ret = zt_wlan_mgmt_rx_frame(ppkt);
            if (ret > 0)
            {
                rx_info->rx_mgnt_pkt++;
            }

            break;

        case ZT_80211_FTYPE_CTL:
            LOG_I("ctrl frame <len:%d>, dropped!!", ppkt->len);
            break;

        default :
            LOG_E("Error Frame Type!! <%d> <len:%d>", frame_type, ppkt->len);
            break;

    }
    return ret;
}


zt_inline zt_s32 zt_rx_cmd_check(zt_u8 *pbuf, zt_u16 skb_len)
{
    zt_u16 pkt_len;
    struct rxd_detail_new *prxd = NULL;
    prxd = (struct rxd_detail_new *)pbuf;

    pkt_len = RXDESC_SIZE + prxd->drvinfo_size * 8 + prxd->pkt_len - 8;

    if (pkt_len != skb_len)
    {
        return -1;
    }

    return 0;
}


zt_inline zt_s32 zt_rx_data_len_check(nic_info_st *pnic_info, zt_u8 *pbuf,
                                      zt_u16 skb_len)
{
    struct rxd_detail_new *prxd = (struct rxd_detail_new *)pbuf;
    zt_u16 pkt_len;

    if (pbuf == NULL)
    {
        return -1;
    }

    if (prxd->crc32)
    {
        if (pnic_info)
        {
            rx_info_t *rx_info = pnic_info->rx_info;
            if (rx_info)
            {
                rx_info->rx_crcerr_pkt++;
            }
        }
        LOG_E("crc check error !!");
        return -1;
    }

    if (prxd->notice == 1)
    {
        pkt_len = RXDESC_SIZE + prxd->pkt_len;
        return -1;
    }
    else
    {
        pkt_len = RXDESC_SIZE + prxd->drvinfo_size * 8 + prxd->pkt_len;
        if (zt_rx_data_type(pbuf) != ZT_PKT_TYPE_FRAME)
        {
            pkt_len -= 8;
        }
    }

    if (pkt_len > skb_len)
    {
        LOG_E("rxd[0]:0x%08x   rxd[1]:0x%08x   prxd->pkt_len:%d", ((zt_s32 *)prxd)[0],
              ((zt_s32 *)prxd)[1], prxd->pkt_len);
        LOG_E("zt_rx_data_len_check error !! pkt_len:%d, skb_len:%d", pkt_len, skb_len);
        return -1;
    }

    return pkt_len;
}


zt_inline zt_u16 zt_rx_get_pkt_len_and_check_valid(zt_u8 *buf, zt_u16 remain,
        zt_bool *valid, zt_bool *notice)
{
    zt_u16 pkt_len;

    struct rxd_detail_new *prxd = (struct rxd_detail_new *)buf;

    pkt_len = RXDESC_SIZE + prxd->drvinfo_size * 8 + prxd->pkt_len;
    if ((prxd->pkt_len == 0) || (prxd->drvinfo_size != 4) ||
            (prxd->cmd_index != 0) || (prxd->crc32 == 1) || (pkt_len > remain))
    {
        *valid = zt_false;
    }
    else
    {
        if (prxd->notice == 1)
        {
            *notice = zt_true;
            *valid = zt_false;
        }
        else
        {
            *valid = zt_true;
            *notice = zt_true;
        }
    }

    return pkt_len;
}



zt_inline PKT_TYPE_T zt_rx_data_type(zt_u8 *pbuf)
{
    zt_u8 u8Value;

    u8Value = zt_le_u8_read(pbuf);

    return (PKT_TYPE_T)(u8Value & 0x03);
}

void zt_rx_rxd_prase(zt_u8 *pbuf, struct rx_pkt *prx_pkt)
{
    struct rx_pkt_info *pinfo = &prx_pkt->pkt_info;
    struct rxd_detail_new *prxd = (struct rxd_detail_new *)pbuf;
    zt_memcpy(prx_pkt->rxd_raw_buf, pbuf, RXDESC_SIZE);

    pinfo->seq_num = prxd->seq;
    pinfo->pkt_len = prxd->pkt_len;
    pinfo->amsdu = prxd->amsdu;
    pinfo->qos_flag = prxd->qos;
    pinfo->more_data = prxd->more_data;
    pinfo->frag_num = prxd->frag;
    pinfo->more_frag = prxd->more_frag;
    pinfo->encrypt_algo = prxd->encrypt_algo;
    pinfo->usb_agg_pktnum = prxd->usb_agg_pktnum;
    pinfo->phy_status = prxd->phy_status;
    pinfo->hif_hdr_len = RXD_SIZE + prxd->drvinfo_size * 8;
    pinfo->qos_pri = prxd->tid;
    pinfo->rx_rate = calc_rx_rate(prxd->rx_rate);
}

zt_s32 zt_rx_action_ba_ctl_init(nic_info_st *nic_info)
{
    zt_u8 tid = 0;
    recv_ba_ctrl_st *ba_ctl = NULL;
    rx_reorder_queue_st *order_node = NULL;
    rx_info_t *rx_info = NULL;
    zt_s32 i = 0;

    if (NULL == nic_info)
    {
        return ZT_RETURN_FAIL;
    }

    rx_info = nic_info->rx_info;
    for (tid  = 0; tid  < TID_NUM; tid++)
    {
        ba_ctl                  = &rx_info->ba_ctl[tid];
        ba_ctl->enable          = zt_false;
        ba_ctl->indicate_seq    = 0xffff;
        ba_ctl->wend_b          = 0xffff;
        ba_ctl->wsize_b         =
            64;/* max_ampdu_sz; */ /* ex. 32(kbytes) -> wsize_b = 32 */
        ba_ctl->ampdu_size      = 0xff;
        ba_ctl->nic_node        = nic_info;
        ba_ctl->timer_start     = zt_false;
        ba_ctl->drop_pkts       = 0;
        ba_ctl->upload_func     = NULL;
        zt_que_init(&ba_ctl->pending_reorder_queue, ZT_LOCK_TYPE_NONE);
        zt_que_init(&ba_ctl->free_order_queue, ZT_LOCK_TYPE_NONE);
        zt_lock_init(&ba_ctl->pending_get_de_queue_lock, ZT_LOCK_TYPE_BH);

        //zt_os_api_timer_reg(&ba_ctl->reordering_ctrl_timer, (void *)rx_reorder_timeout_handle, ba_ctl);
        zt_os_api_timer_reg(&ba_ctl->reordering_ctrl_timer, rx_reorder_timeout_handle,
                            &ba_ctl->reordering_ctrl_timer);

        for (i = 0; i < BA_REORDER_QUEUE_NUM; i++)
        {
            order_node = zt_kzalloc(sizeof(rx_reorder_queue_st));
            if (NULL == order_node)
            {
                LOG_E("[%s] zt_kzalloc failed", __func__);
                break;
            }
            order_node->pskb = NULL;
            zt_enque_tail(&order_node->list, &ba_ctl->free_order_queue);

        }

    }

    return ZT_RETURN_OK;
}

zt_s32 rx_free_reorder_empty(recv_ba_ctrl_st *ba_ctl)
{
    zt_que_t *queue_head     = NULL;
    zt_s32 ret = 0;
    if (NULL == ba_ctl)
    {
        return 0;
    }

    queue_head = &ba_ctl->free_order_queue;

    ret =  zt_que_is_empty(queue_head);
    return ret;
}

rx_reorder_queue_st *rx_free_reorder_dequeue(recv_ba_ctrl_st *ba_ctl)
{
    zt_que_t *queue_head = NULL;
    zt_list_t *phead       = NULL;
    zt_list_t *plist       = NULL;
    rx_reorder_queue_st *tmp = NULL;

    if (NULL == ba_ctl)
    {
        return NULL;
    }


    if (rx_free_reorder_empty(ba_ctl))
    {
        return NULL;
    }

    queue_head = &ba_ctl->free_order_queue;
    zt_lock_lock(&queue_head->lock);
    phead = zt_que_list_head(queue_head);
    plist = zt_list_next(phead);

    tmp = ZT_CONTAINER_OF(plist, rx_reorder_queue_st, list);
    if (tmp)
    {
        queue_head->cnt--;
        zt_list_delete(plist);
    }
    zt_lock_unlock(&queue_head->lock);
    return tmp;
}

zt_s32 rx_free_reorder_enqueue(recv_ba_ctrl_st *ba_ctl,
                               rx_reorder_queue_st *node)
{
    zt_que_t *queue_head = NULL;
    zt_list_t *phead       = NULL;
    zt_list_t *plist       = NULL;

    if (NULL == ba_ctl || NULL == node)
    {
        return -1;
    }

    queue_head = &ba_ctl->free_order_queue;
    zt_lock_lock(&queue_head->lock);
    phead = zt_que_list_head(queue_head);
    plist = zt_list_next(phead);

    queue_head->cnt++;
    zt_list_insert_tail(&node->list, plist);
    zt_lock_unlock(&queue_head->lock);

    return 0;
}

void rx_do_update_expect_seq(zt_u16 seq_num, recv_ba_ctrl_st   *ba_order)
{
    if (NULL == ba_order)
    {
        return ;
    }
    ba_order->indicate_seq = (seq_num + 1) & 0xFFF;
    //ba_order->wend_b = (ba_order->indicate_seq + ba_order->wsize_b - 1) & 0xFFF;
}

zt_s32 rx_pending_reorder_is_empty(recv_ba_ctrl_st   *ba_order)
{
    zt_list_t  *phead = NULL;
    zt_que_t *queue_head  = NULL;
    zt_s32 ret = 0;
    if (NULL == ba_order)
    {
        return zt_true;
    }
    queue_head  = &ba_order->pending_reorder_queue;

    zt_lock_lock(&queue_head->lock);
    phead = zt_que_list_head(queue_head);
    ret =  zt_list_is_empty(phead);
    zt_lock_unlock(&queue_head->lock);

    return ret;
}
zt_s32 rx_pending_reorder_enqueue(zt_u16 current_seq, void *pskb,
                                  recv_ba_ctrl_st   *ba_order)
{
    zt_list_t  *phead = NULL;
    zt_list_t  *pos = NULL;
    rx_reorder_queue_st *pprev_pkt = NULL;
    rx_reorder_queue_st *new_pkt   = NULL;

    zt_u16 seq_num = 0;
    zt_s32 find_flag = 0;
    zt_que_t *queue_head  = NULL;

    if (NULL == ba_order || NULL == pskb)
    {
        LOG_E("[%s] ba_order or pskb is null", __func__);
        return REORDER_DROP;
    }

    queue_head  = &ba_order->pending_reorder_queue;
    zt_lock_lock(&queue_head->lock);
    phead = zt_que_list_head(queue_head);
    zt_list_for_each_prev(pos, phead)
    {
        pprev_pkt = ZT_CONTAINER_OF(pos, rx_reorder_queue_st, list);
        if (pprev_pkt)
        {
            seq_num = pprev_pkt->seq_num;
            //LOG_I("[%s] cur seq:%d, seq:%d", __func__, prx_pkt_info->seq_num , seq_num);

            if (SN_EQUAL(seq_num, current_seq))//dup
            {
                ba_order->drop_pkts++;
                LOG_W("[%s]: dup the packet, seq:%d", __func__, current_seq);
                zt_lock_unlock(&queue_head->lock);
                return -1;
            }
            else if (SN_LESS(current_seq, seq_num))//continue
            {

            }
            else //revert
            {
                find_flag = 1;
                break;

            }
        }
        pprev_pkt = NULL;
    }
    zt_lock_unlock(&queue_head->lock);

    new_pkt = rx_free_reorder_dequeue(ba_order);
    while (NULL == new_pkt)
    {
        LOG_W("waite for rx_free_reorder_dequeue,%d,%d",
              zt_que_count(&ba_order->pending_reorder_queue),
              zt_que_count(&ba_order->free_order_queue));
        //zt_msleep(ba_order->wait_timeout);
        new_pkt = rx_free_reorder_dequeue(ba_order);
    }

    new_pkt->seq_num = current_seq;
    new_pkt->pskb = pskb;

    zt_lock_lock(&queue_head->lock);
    queue_head->cnt++;
    if (0 == find_flag)
    {
        //LOG_I("insert <p:%d> seq_num:%d [%d, %d]", new_pkt->qos_pri, new_pkt->seq_num, ba_order->indicate_seq, ba_order->wend_b);
        zt_list_insert_head(&new_pkt->list, phead);
    }
    else
    {
        //LOG_I("insert <p:%d> seq_num:%d prev <p:%d> seq_num:%d [%d, %d]", new_pkt->qos_pri, new_pkt->seq_num, pprev_pkt->qos_pri, pprev_pkt->seq_num, ba_order->indicate_seq, ba_order->wend_b);
        zt_list_insert_head(&new_pkt->list, &pprev_pkt->list);
    }

    zt_lock_unlock(&queue_head->lock);

    return 0;

}

rx_reorder_queue_st *rx_pending_reorder_dequeue(recv_ba_ctrl_st   *ba_order)
{
    zt_list_t *phead = NULL;
    zt_list_t *plist = NULL;
    zt_que_t *queue_head = NULL;
    rx_reorder_queue_st *tmp = NULL;

    if (NULL == ba_order)
    {
        return NULL;
    }

    if (rx_pending_reorder_is_empty(ba_order))
    {
        return NULL;
    }

    queue_head = &ba_order->pending_reorder_queue;

    zt_lock_lock(&queue_head->lock);
    phead = zt_que_list_head(queue_head);
    plist = zt_list_next(phead);

    tmp = ZT_CONTAINER_OF(plist, rx_reorder_queue_st, list);

    if (tmp)
    {
        queue_head->cnt--;
        zt_list_delete(plist);
    }
    zt_lock_unlock(&queue_head->lock);
    return tmp;
}
rx_reorder_queue_st *rx_pending_reorder_getqueue(recv_ba_ctrl_st   *ba_order)
{
    zt_list_t *phead = NULL;
    zt_list_t *plist = NULL;
    zt_que_t *queue_head = NULL;

    if (NULL == ba_order)
    {
        return NULL;
    }


    if (rx_pending_reorder_is_empty(ba_order))
    {
        return NULL;
    }

    queue_head = &ba_order->pending_reorder_queue;
    zt_lock_lock(&queue_head->lock);
    phead = zt_que_list_head(queue_head);
    plist = zt_list_next(phead);
    zt_lock_unlock(&queue_head->lock);

    return ZT_CONTAINER_OF(plist, rx_reorder_queue_st, list);
}

zt_s32 rx_pending_reorder_get_cnt(recv_ba_ctrl_st   *ba_order)
{
    zt_que_t *queue_head = NULL;
    zt_s32 ret = 0;
    if (NULL == ba_order)
    {
        return -1;
    }

    queue_head = &ba_order->pending_reorder_queue;
    zt_lock_lock(&queue_head->lock);

    ret = queue_head->cnt;
    zt_lock_unlock(&queue_head->lock);

    return ret;
}


zt_s32 rx_do_chk_expect_seq(zt_u16 seq_num, recv_ba_ctrl_st   *ba_order)
{
    if (NULL == ba_order)
    {
        return REORDER_DROP;
    }

    if (ba_order->indicate_seq == 0xFFFF)
    {
        ba_order->indicate_seq = seq_num;
    }

    ba_order->wend_b = (ba_order->indicate_seq + ba_order->wsize_b - 1) & 0xFFF;

    //LOG_I("[%s]: current seq is %d", __func__, seq_num);
    if (SN_EQUAL(seq_num, ba_order->indicate_seq))
    {
        ba_order->indicate_seq = (ba_order->indicate_seq + 1) & 0xFFF;
    }
    else if (SN_LESS(seq_num, ba_order->indicate_seq))//drop
    {
        //LOG_I("seq:%d indicate_seq:%d", seq_num, ba_order->indicate_seq);
        ba_order->drop_pkts++;
        return REORDER_DROP;
    }
    else if (SN_LESS(ba_order->wend_b, seq_num))
    {
        if (seq_num >= (ba_order->wsize_b - 1))
        {
            ba_order->indicate_seq = seq_num + 1 - ba_order->wsize_b;
            //LOG_I("[1] recv_seq:%d  update indicate_seq :%d", seq_num, ba_order->indicate_seq);
        }
        else
        {
            ba_order->indicate_seq = 0xFFF - (ba_order->wsize_b - (seq_num + 1)) + 1;
            //LOG_I("[2] recv_seq:%d update indicate_seq :%d", seq_num, ba_order->indicate_seq);
        }
    }

    return REORDER_ENQUE;
}

zt_s32 zt_rx_action_ba_ctl_deinit(nic_info_st *nic_info)
{
    zt_u8 tid                       = 0;
    zt_list_t *pos                  = NULL;
    zt_list_t *next                 = NULL;
    zt_list_t *phead                = NULL;
    recv_ba_ctrl_st *ba_ctl         = NULL;
    rx_info_t       *rx_info        = NULL;
    rx_reorder_queue_st *order_node = NULL;
    zt_que_t   *queue_head          = NULL;

    if (NULL == nic_info)
    {
        return -1;
    }

    rx_info = nic_info->rx_info;

    LOG_I("[%s] handle", __func__);
    for (tid  = 0; tid  < TID_NUM; tid++)
    {
        ba_ctl                  = &rx_info->ba_ctl[tid];
        if (NULL == ba_ctl)
        {
            continue;
        }
        zt_lock_lock(&ba_ctl->pending_get_de_queue_lock);
        if (zt_false == rx_pending_reorder_is_empty(ba_ctl))
        {
            LOG_I("start free pending_reorder_queue");
            while (1)
            {
                order_node = rx_pending_reorder_dequeue(ba_ctl);
                if (NULL == order_node)
                {
                    break;
                }
                if (NULL == order_node->pskb)
                {
                    ba_ctl->free_skb(nic_info, order_node->pskb);
                    order_node->pskb = NULL;
                }
                zt_kfree(order_node);
                order_node = NULL;
            }
        }

        if (rx_free_reorder_empty(ba_ctl))
        {
            zt_lock_unlock(&ba_ctl->pending_get_de_queue_lock);
            continue;
        }

        LOG_I("[%s, %d]", __func__, __LINE__);

        queue_head = &ba_ctl->free_order_queue;
        phead = zt_que_list_head(queue_head);
        zt_lock_lock(&queue_head->lock);
        zt_list_for_each_safe(pos, next, phead)
        {
            order_node = zt_list_entry(pos, rx_reorder_queue_st, list);
            if (order_node)
            {
                zt_kfree(order_node);
                order_node = NULL;
            }
            pos = NULL;
        }
        zt_lock_unlock(&queue_head->lock);
        zt_lock_unlock(&ba_ctl->pending_get_de_queue_lock);

    }

    return ZT_RETURN_OK;
}

zt_s32 zt_rx_ba_reinit(nic_info_st *nic_info, zt_u8 tid)
{
    recv_ba_ctrl_st *ba_ctl         = NULL;
    rx_info_t       *rx_info        = NULL;
    rx_reorder_queue_st *order_node = NULL;

    if (NULL == nic_info)
    {
        return -1;
    }

    if (tid >= TID_NUM)
    {
        return -2;
    }

    rx_info = nic_info->rx_info;
    if (NULL == rx_info)
    {
        return -3;
    }

    ba_ctl  = &rx_info->ba_ctl[tid];
    if (NULL == ba_ctl)
    {
        return -4;
    }

    zt_lock_lock(&ba_ctl->pending_get_de_queue_lock);
    // LOG_I("[%s]: reinit ba_ctl tid:%d", __func__, tid);
    ba_ctl->enable          = zt_false;
    ba_ctl->indicate_seq    = 0xffff;
    ba_ctl->wend_b          = 0xffff;
    if (zt_false == rx_pending_reorder_is_empty(ba_ctl))
    {
        LOG_I("start free pending_reorder_queue");
        while (1)
        {
            order_node = rx_pending_reorder_dequeue(ba_ctl);
            if (NULL == order_node)
            {
                break;
            }
            if (NULL == order_node->pskb)
            {
                ba_ctl->free_skb(nic_info, order_node->pskb);
                order_node->pskb = NULL;
            }

            rx_free_reorder_enqueue(ba_ctl, order_node);
            order_node = NULL;

        }
    }

    zt_lock_unlock(&ba_ctl->pending_get_de_queue_lock);

    return 0;
}

void zt_rx_ba_all_reinit(nic_info_st *nic_info)
{
    zt_u8 tid;

    for (tid  = 0; tid  < TID_NUM; tid++)
    {
        zt_rx_ba_reinit(nic_info, tid);
    }
}

zt_s32 rx_reorder_upload(recv_ba_ctrl_st   *ba_order)
{
    zt_s32 tmp_ret = 0;
    nic_info_st *nic_info = ba_order->nic_node;

    //LOG_I("[%s, %d]", __func__, __LINE__);
    if (NULL == nic_info)
    {
        return -1;
    }

    while (1)
    {
        rx_reorder_queue_st *get_reorder = NULL;

        get_reorder = rx_pending_reorder_getqueue(ba_order);
        if (NULL == get_reorder)
        {
            break;
        }

        if (!SN_LESS(ba_order->indicate_seq, get_reorder->seq_num))
        {
            rx_reorder_queue_st *de_reorder = NULL;
            de_reorder = rx_pending_reorder_dequeue(ba_order);
            if (de_reorder != get_reorder)
            {
                LOG_I("[%s, %d]", __func__, __LINE__);
                rx_pending_reorder_enqueue(de_reorder->seq_num, de_reorder->pskb, ba_order);
                break;
            }


            if (SN_EQUAL(ba_order->indicate_seq, de_reorder->seq_num))
            {
                ba_order->indicate_seq = (ba_order->indicate_seq + 1) & 0xFFF;
                //LOG_I("update indicate_seq <p:%d> %d", de_reorder->qos_pri, ba_order->indicate_seq);
            }

            if (de_reorder->pskb)
            {
                ba_order->upload_func(nic_info, de_reorder->pskb);
            }
            //LOG_I("out order <p:%d> seq:%d", de_reorder->qos_pri, de_reorder->seq_num);
            rx_free_reorder_enqueue(ba_order, de_reorder);

            tmp_ret = 0;
        }
        else
        {
            tmp_ret = rx_pending_reorder_get_cnt(ba_order);
            break;
        }

    }

    return tmp_ret;
}

void rx_reorder_timeout_handle(zt_os_api_timer_t *timer)
{
    recv_ba_ctrl_st   *ba_order = ZT_CONTAINER_OF((zt_os_api_timer_t *)timer,
                                  recv_ba_ctrl_st, reordering_ctrl_timer);
    zt_u8 pktCnt_inQueue = 0;
    rx_reorder_queue_st *get_reorder = NULL;
    if (NULL == ba_order)
    {
        return;
    }

    zt_lock_lock(&ba_order->pending_get_de_queue_lock);
    get_reorder = rx_pending_reorder_getqueue(ba_order);
    if (NULL == get_reorder)
    {
        zt_lock_unlock(&ba_order->pending_get_de_queue_lock);
        return;
    }
    //LOG_I("[%s] indicate_seq:%d, seq_num:%d", __func__, ba_order->indicate_seq, get_reorder->seq_num);
    ba_order->indicate_seq = get_reorder->seq_num;

    pktCnt_inQueue = rx_reorder_upload(ba_order);
    if (pktCnt_inQueue != 0)
    {
        //LOG_W("%d pkts in order queue(%s)", pktCnt_inQueue, __func__);
        zt_os_api_timer_set(&ba_order->reordering_ctrl_timer, ba_order->wait_timeout);
    }
    zt_lock_unlock(&ba_order->pending_get_de_queue_lock);
}

void zt_rx_data_reorder_core(rx_pkt_t *pkt)
{
    zt_s32 ret = 0;
    wdn_net_info_st *pwdn_info = NULL;
    zt_s32 seq_num = 0;
    zt_u8 pktCnt_inQueue = 0;
    zt_s32 prio    = 0;
    recv_ba_ctrl_st *ba = NULL;

    if (NULL == pkt || NULL == pkt->pskb)
    {
        LOG_E("[%s]: skb is null, drop it", __func__);
        return;
    }


    pwdn_info = pkt->wdn_info;
    if (NULL == pwdn_info)
    {
        LOG_E("[%s] pwdn_info is null", __func__);
        return;
    }

    prio   = pkt->pkt_info.qos_pri;
    ba = &pwdn_info->ba_ctl[prio];
    if (NULL == ba)
    {
        LOG_E("[%s] ba ", __func__);
        return;
    }

    zt_lock_lock(&ba->pending_get_de_queue_lock);
    seq_num = pkt->pkt_info.seq_num;
    ret = rx_do_chk_expect_seq(seq_num, ba);
    if (REORDER_ENQUE == ret)
    {
        //LOG_I("pri:%d enqueue seq:%d  indicate:%d", prio, seq_num, ba->indicate_seq);
        ret = rx_pending_reorder_enqueue(seq_num, pkt->pskb, ba);
        // if (ret < 0) {
        //     LOG_E("[%s]: pending packet error", __func__);
        // }
    }
    else
    {
        ;//LOG_E("drop packet");
    }

    if (ret < 0)
    {
        if (pkt->pskb)
        {
            ba->free_skb(pkt->p_nic_info, pkt->pskb);
            pkt->pskb = NULL;
        }
        zt_lock_unlock(&ba->pending_get_de_queue_lock);
        return;
    }

    pktCnt_inQueue = rx_reorder_upload(ba);
    if (pktCnt_inQueue != 0)
    {
        //LOG_W("%d pkts in order queue(%s)", pktCnt_inQueue, __func__);
        zt_os_api_timer_set(&ba->reordering_ctrl_timer, ba->wait_timeout);
    }
    zt_lock_unlock(&ba->pending_get_de_queue_lock);
}



static zt_s8 cal_ant_cck_rssi_pwr(zt_u8 lna_idx, zt_u8 vga_idx)
{
    zt_s8 rx_pwr_all = 0x00;

    switch (lna_idx)
    {
        case 7:
            if (vga_idx <= 27)
            {
                rx_pwr_all = -100 + 2 * (27 - vga_idx);
            }
            else
            {
                rx_pwr_all = -100;
            }
            break;
        case 5:
            rx_pwr_all = -74 + 2 * (21 - vga_idx);
            break;
        case 3:
            rx_pwr_all = -60 + 2 * (20 - vga_idx);
            break;
        case 1:
            rx_pwr_all = -44 + 2 * (19 - vga_idx);
            break;
        default:
            //LOG_W("[%s] lna_idx:%d, vga_index:%d", __func__, lna_idx, vga_idx);
            break;
    }

    return rx_pwr_all;
}
static zt_u8 query_rxpwr_percentage(zt_s8 AntPower)
{
    zt_u8 percent = 0;

    if ((AntPower <= -100) || (AntPower >= 20))
    {
        percent =  0;
    }
    else if (AntPower >= 0)
    {
        percent =  100;
    }
    else
    {
        percent =  100 + AntPower;
    }

    return percent;
}
static zt_u8 cal_evm2percentage(zt_s8 Value)
{
    zt_s8 ret_val;

    ret_val = Value;
    ret_val /= 2;

#ifdef MSG_EVM_ENHANCE_ANTDIV
    if (ret_val >= 0)
    {
        ret_val = 0;
    }

    if (ret_val <= -40)
    {
        ret_val = -40;
    }

    ret_val = 0 - ret_val;
    ret_val *= 3;
#else
    if (ret_val >= 0)
    {
        ret_val = 0;
    }

    if (ret_val <= -33)
    {
        ret_val = -33;
    }

    ret_val = 0 - ret_val;
    ret_val *= 3;

    if (ret_val == 99)
    {
        ret_val = 100;
    }
#endif

    return ret_val;
}

zt_s32 zt_rx_calc_str_and_qual(nic_info_st *nic_info, zt_u8 agc_gain,
                               zt_u8 sig_qual_or_pwdb, zt_u8 agc_rpt_or_cfosho,
                               zt_s8 rx_evm, void *prx_pkt)
{
    prx_pkt_t ppt       = (prx_pkt_t)prx_pkt;
    zt_bool is_cck_rate = zt_false;
    zt_u8 rate_cacl     = 0;
    zt_u8 lna_index     = 0;
    zt_u8 vga_index     = 0;
    zt_s8 rx_pwr        = 0;
    zt_u8 pwdb_all      = 0;

    rate_cacl = ppt->pkt_info.rx_rate;

    is_cck_rate = (rate_cacl <= DESC_RATE11M) ? zt_true : zt_false;
    if (is_cck_rate)
    {
        lna_index   = ((agc_rpt_or_cfosho & 0xE0) >> 5);
        vga_index   = agc_rpt_or_cfosho & 0x1F;
        rx_pwr      = cal_ant_cck_rssi_pwr(lna_index, vga_index);
        pwdb_all    = query_rxpwr_percentage(rx_pwr);

        if (pwdb_all > 40)
        {
            ppt->phy_status.signal_qual = 100;
        }
        else
        {
            if (sig_qual_or_pwdb > 64)
            {
                ppt->phy_status.signal_qual = 0;
            }
            else if (sig_qual_or_pwdb < 20)
            {
                ppt->phy_status.signal_qual = 100;
            }
            else
            {
                ppt->phy_status.signal_qual = (64 - sig_qual_or_pwdb) * 100 / 44;
            }
        }

#ifdef CONFIG_SIGNAL_SCALE_MAPPING
        ppt->phy_status.signal_strength = signal_scale_mapping(pwdb_all);
#else
        ppt->phy_status.signal_strength = pwdb_all;
#endif
    }
    else
    {
        zt_u8 evm       = 0;
        zt_u8 rssi      = 0;
        zt_s8 tmp_rx_pwr = (agc_gain & 0x3F) * 2  - 110;
        rssi            = query_rxpwr_percentage(tmp_rx_pwr);
        rx_pwr          = ((sig_qual_or_pwdb >> 1) & 0x7F) - 110;
        pwdb_all        = query_rxpwr_percentage(rx_pwr);
        evm             = cal_evm2percentage(rx_evm);

        ppt->phy_status.signal_qual = evm & 0xFF;

#ifdef CONFIG_SIGNAL_SCALE_MAPPING
        ppt->phy_status.signal_strength = signal_scale_mapping(rssi);
#else
        ppt->phy_status.signal_strength = rssi;
#endif

    }

#if 0
    ppt->phy_status.signal_strength = signal_scale_mapping(
                                          ppt->phy_status.signal_strength);
    ppt->phy_status.rssi            = translate_percentage_to_dbm(
                                          ppt->phy_status.signal_strength);
#endif

    return ZT_RETURN_OK;
}

zt_s32 zt_rx_suspend(nic_info_st *pnic_info)
{
    pwr_info_st *pm      = NULL;
    hw_info_st *hw_info = NULL;
    zt_u8 tid = 0;
    recv_ba_ctrl_st *ba_ctl = NULL;
    rx_info_t *rx_info  = NULL;
    if (NULL == pnic_info)
    {
        return 0;
    }

    pm = pnic_info->pwr_info;
    if (zt_false == pm->bInSuspend)
    {
        return 0;
    }

    hw_info = pnic_info->hw_info;
    rx_info = pnic_info->rx_info;
    LOG_I("[%s,%d clear rx data", __func__, __LINE__);
    if (zt_true == hw_info->ba_enable)
    {
        zt_rx_ba_all_reinit(pnic_info);
        for (tid = 0; tid < TID_NUM; tid++)
        {
            ba_ctl = &rx_info->ba_ctl[tid];
            zt_os_api_timer_unreg(&ba_ctl->reordering_ctrl_timer);
        }
    }

    return 0;
}

zt_s32 zt_rx_resume(nic_info_st *pnic_info)
{
    pwr_info_st *pm      = NULL;
    hw_info_st *hw_info = NULL;
    zt_u8 tid = 0;
    recv_ba_ctrl_st *ba_ctl = NULL;
    rx_info_t *rx_info  = NULL;
    if (NULL == pnic_info)
    {
        return 0;
    }

    pm = pnic_info->pwr_info;
    if (zt_false == pm->bInSuspend)
    {
        return 0;
    }

    hw_info = pnic_info->hw_info;
    rx_info = pnic_info->rx_info;
    LOG_I("[%s,%d clear rx data", __func__, __LINE__);
    if (zt_true == hw_info->ba_enable)
    {
        for (tid = 0; tid < TID_NUM; tid++)
        {
            ba_ctl = &rx_info->ba_ctl[tid];
            zt_os_api_timer_reg(&ba_ctl->reordering_ctrl_timer, rx_reorder_timeout_handle,
                                &ba_ctl->reordering_ctrl_timer);
        }
    }

    return 0;
}


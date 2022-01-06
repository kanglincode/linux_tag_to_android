/*
 * mcu_cmd.h
 *
 * used for cmd Interactive command
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
#ifndef __MCU_CMD_H__
#define __MCU_CMD_H__

#define mcu_cmd_communicate        zt_io_write_cmd_by_mailbox
#define mcu_cmd_communicate_try    zt_io_write_cmd_by_mailbox_try


#define ZT_MAILBOX_INT_FINISH       0x03E8
#define ZT_MAILBOX_REG_INT          0x03F0

#define MAILBOX_REG_START       0x00000300
#define MAILBOX_WORD_LEN        4

#define MAILBOX_REG_FUNC        (MAILBOX_REG_START)
#define MAILBOX_ARG_START       (MAILBOX_REG_FUNC + MAILBOX_WORD_LEN)

#define MAILBOX_MAX_TXLEN       (56 - 3)

#define SHORT_SLOT_TIME                 9
#define NON_SHORT_SLOT_TIME             20


enum
{
    FW_STATE_NOLINK = 0,
    FW_STATE_ADHOC = 1,
    FW_STATE_STATION = 2,
    FW_STATE_AP = 3,
    FW_STATE_MONITOR = 4,
    FW_STATE_NO_EXIST = 0xAA,
};


enum _REG_PREAMBLE_MODE
{
    PREAMBLE_LONG = 1,
    PREAMBLE_AUTO = 2,
    PREAMBLE_SHORT = 3,
};

typedef enum _UMSG_OPS_CODE
{
    FUNC_REPLY                                      = 0x0,
    UMSG_OPS_READ_VERSION                           = 0x01,
    UMSG_OPS_HAL_CCA_CONFIG                         = 0x1A,    // sdio
    UMSG_OPS_HAL_SET_HWREG                          = 0x1C,    // sdio
    UMSG_OPS_HAL_GET_HWREG                          = 0x1D,    // sdio

    UMSG_OPS_HAL_MSG_WDG                            = 0x20,
    UMSG_OPS_HAL_WRITEVAR_MSG                       = 0x21,
    UMSG_OPS_HAL_READVAR_MSG                        = 0x22,   // check mp mode use
    UMSG_OPS_MSG_SET_RATE_BITMAP                    = 0x29,
    UMSG_OPS_HAL_GET_MSG_STA_INFO                   = 0x2D,
    UMSG_OPS_HAL_SYNC_MSG_STA_INFO                  = 0x2E,
    UMSG_OPS_HAL_ARS_INIT                           = 0x2F,
    UMSG_OPS_HAL_GET_CHNLBW_MODE                    = 0x43,
    UMSG_OPS_HAL_CALI_LLC                           = 0x45,
    UMSG_OPS_HAL_PHY_IQ_CALIBRATE                   = 0x46,
    UMSG_OPS_HAL_CHNLBW_MODE                        = 0x48,
    UMSG_OPS_HAL_FW_INIT                            = 0x4B,
    UMSG_OPS_HAL_UPDATE_THERMAL                     = 0x4C,
    UMSG_OPS_HAL_SET_BCN_REG                        = 0x51,
    UMSG_OPS_HAL_SET_MAC                            = 0x54,
    UMSG_OPS_HAL_SET_BSSID                          = 0x55,

    UMSG_OPS_HAL_SET_BCN                            = 0x56,
    UMSG_OPS_HW_SET_BASIC_RATE                      = 0x57,
    UMSG_OPS_HW_SET_OP_MODE                         = 0x58,
    UMSG_OPS_HW_SET_CORRECT_TSF                     = 0x59,
    UMSG_OPS_HW_SET_MLME_DISCONNECT                 = 0x5a,
    UMSG_OPS_HW_SET_MLME_SITE                       = 0x5b,
    UMSG_OPS_HW_SET_MLME_JOIN                       = 0x5c,
    UMSG_OPS_HW_SET_DK_CFG                          = 0x5f,

    UMSG_OPS_HAL_SEC_WRITE_CAM                      = 0x68,
    UMSG_OPS_HAL_CONTROL_ARS_CMD                    = 0x69,
    UMSG_OPS_HAL_CHECK_TXBUFF_EMPTY                 = 0x6c,

    UMSG_OPS_HAL_LPS_OPT                            = 0x7B,
    UMSG_OPS_HAL_LPS_CONFIG                         = 0x7C,
    UMSG_OPS_HAL_LPS_SET                            = 0x7D,
    UMSG_OPS_HAL_LPS_GET                            = 0x7E,

    UMSG_OPS_HAL_CONFIG_XMIT                        = 0X8C,
    UMSG_OPS_HAL_SET_USB_AGG_NORMAL                 = 0X8D,
    UMSG_OPS_HAL_SET_USB_AGG_CUSTOMER               = 0X8E,

    UMSG_OPS_MP_EFUSE_GET                           = 0XAF,//phy
    UMSG_OPS_MP_USER_INFO                           = 0XF0,
    UMSG_OPS_RESET_CHIP                             = 0XF2,
    UMSG_OPS_HAL_DBGLOG_CONFIG                      = 0xF6,
    UMSG_OPS_ARS_DBG_INFO                           = 0xF7,
    UMSG_OPS_ARS_SWITCH                             = 0xF8,
    UMSG_OPS_ARS_SET                                = 0xF9,
} MCU_UMSG_CMD;

#define WLAN_HAL_VALUE_MEDIA_STATUS         0
#define WLAN_HAL_VALUE_MEDIA_STATUS1        1
#define WLAN_HAL_VALUE_CORRECT_TSF          9
#define WLAN_HAL_VALUE_ON_RCR_AM            14
#define WLAN_HAL_VALUE_OFF_RCR_AM           15
#define WLAN_HAL_VALUE_BEACON_INTERVAL      16
#define WLAN_HAL_VALUE_SLOT_TIME            17
#define WLAN_HAL_VALUE_RESP_SIFS            18
#define WLAN_HAL_VALUE_ACK_PREAMBLE         19
#define WLAN_HAL_VALUE_SEC_CFG              20
#define WLAN_HAL_VALUE_BCN_VALID            22
#define WLAN_HAL_VALUE_CAM_INVALID_ALL      25
#define WLAN_HAL_VALUE_AC_PARAM_VO          26
#define WLAN_HAL_VALUE_AC_PARAM_VI          27
#define WLAN_HAL_VALUE_AC_PARAM_BE          28
#define WLAN_HAL_VALUE_AC_PARAM_BK          29
#define WLAN_HAL_VALUE_AMPDU_MIN_SPACE      31
#define WLAN_HAL_VALUE_AMPDU_FACTIONOR      32
#define WLAN_HAL_VALUE_DL_BCN_SEL           65
#define WLAN_HAL_VALUE_MACID_WAKEUP         88
#define WLAN_HAL_VALUE_BCN_VALID1           92



typedef enum _HAL_MSG_VARIABLE
{
    HAL_MSG_STA_INFO,
    HAL_MSG_P2P_STATE,
    HAL_MSG_WIFI_DISPLAY_STATE,
    HAL_MSG_NOISE_MONITOR,
    HAL_MSG_REGULATION,
    HAL_MSG_INITIAL_GAIN,
    HAL_MSG_FA_CNT_DUMP,
    HAL_MSG_DBG_FLAG,
    HAL_MSG_DBG_LEVEL,
    HAL_MSG_RX_INFO_DUMP,
#ifdef CONFIG_AUTO_CHNL_SEL_NHM
    HAL_MSG_AUTO_CHNL_SEL,
#endif
} MSG_BODY_VARIABLE;

#define WIFI_ASOC_STATE                 0x00000001
#define WIFI_STATION_STATE              0x00000008
#define WIFI_AP_STATE                   0x00000010
#define WIFI_ADHOC_STATE                0x00000020
#define WIFI_ADHOC_MASTER_STATE         0x00000040
#define WIFI_UNDER_WPS                  0x00000100
#define WIFI_SITE_MONITOR               0x00000800
#define WIFI_FW_NO_EXIST                0x01000000


/*role*/
#define CONTROL_ARS_STA     1
#define CONTROL_ARS_AP      2
#define CONTROL_ARS_ADHOC   6

#define RSVD_PAGE  0x00
#define RSVD_PAGE_len 5

#define MEDIA_RPT 0x01
#define MEDIA_RPT_LEN 7

typedef struct fw_init_param_
{
    zt_u32 work_mode;
    zt_u32 mac_addr[ZT_80211_MAC_ADDR_LEN];
    zt_u32 concurrent_mode;
    zt_u32 rx_agg_enable;
} hw_param_st;

typedef struct phy_cali_
{
    zt_u8 TxPowerTrackControl;
    zt_s8 Remnant_CCKSwingIdx;
    zt_s8 Remnant_OFDMSwingIdx;
    zt_u8 rsvd;
} phy_cali_t;

typedef struct
{
    zt_u64 tx_bytes;
    zt_u64 rx_bytes;
    zt_u32 cur_wireless_mode;
    zt_u32 CurrentBandType;
    zt_u32 ForcedDataRate;
    zt_u32 nCur40MhzPrimeSC;
    zt_u32 dot11PrivacyAlgrthm;
    zt_u32 CurrentChannelBW;
    zt_u32 CurrentChannel;
    zt_u32 net_closed;
    zt_u32 u1ForcedIgiLb;
    zt_u32 bScanInProcess;
    zt_u32 bpower_saving;
    zt_u32 traffic_stat_cur_tx_tp;
    zt_u32 traffic_stat_cur_rx_tp;
    zt_u32 msgWdgStateVal;
    zt_u32 ability;
    zt_u32 Rssi_Min;
    zt_u32 dig_CurIGValue;
    zt_u32 wifi_direct;
    zt_u32 wifi_display;
    zt_u64 dbg_cmp;
    zt_u32 dbg_level;
    zt_u32 PhyRegPgVersion;
    zt_u32 PhyRegPgValueType;
    phy_cali_t phy_cali;
    zt_u32 bDisablePowerTraining;
    zt_u32 fw_state;
    zt_u32 sta_count;
} mcu_msg_body_st;
typedef struct FALSE_ALARM_STATISTICS_ST_
{
    zt_u32  parity_failed_cnt;
    zt_u32  rate_illegal_cnt;
    zt_u32  crc8_failed_cnt;
    zt_u32  mcs_failed_cnt;
    zt_u32  ofdm_failed_cnt;
    zt_u32  ofdm_pre_failed_cnt;
    zt_u32  cck_failed_cnt;
    zt_u32  all_cnt;
    zt_u32  fast_fsync_cnt;
    zt_u32  sb_search_failed_cnt;
    zt_u32  ofdm_cca_cnt;
    zt_u32  cck_cca_cnt;
    zt_u32  cca_all_cnt;
    zt_u32  bw_usc_cnt;
    zt_u32  bw_lsc_cnt;
} false_cont_info_st, *pfalse_cont_info_st;


typedef struct ars_fw_dbg_info_st_
{
    false_cont_info_st fas;
    zt_u8 noisy_decision;
    zt_u8 tddi_min;
    zt_u8 pwdb;
    zt_u8 change_state;
    zt_u32 pt_scroe;
    zt_u8 cur_igi;
    zt_u8 igi_dynamic_min;
    zt_u8 igi_target;
    zt_u8 rssi_level;
    zt_u32 crsytal_cap;
    zt_s32 cfo_avg_pre;
    zt_u8 thermal_val;
    zt_u8 thermal_lck;
    zt_u8 thermal_iqk;
    zt_u8 dpk_thermal;
    zt_u32 support_ability;
    zt_u32 seq;
    zt_u8 proc_flag;
    zt_u8 force_power_trainging_state;
    zt_u16 NHM_cnt_0;
    zt_u32 end_flag;

} ars_fw_dbg_info_st;

typedef struct ars_fw_set_msg_st_
{
    zt_u32 set_id;
    zt_u32 value;
    zt_u32 seq;
} ars_fw_set_msg_st;

typedef struct
{
    zt_u8  bUsed;
    zt_u32 mac_id;
    zt_u8  hwaddr[ZT_80211_MAC_ADDR_LEN];
    zt_u8  ra_rpt_linked;
    zt_u8  wireless_mode;
    zt_u8  rssi_level;
    zt_u8  ra_change;
    struct wdn_ht_priv htpriv;
} mcu_msg_sta_info_st;




zt_s32 translate_percentage_to_dbm(zt_u32 SignalStrengthIndex);
zt_s32 signal_scale_mapping(zt_s32 current_sig);


zt_s32 zt_mcu_cmd_get_status(nic_info_st *nic_info, zt_u32 cmd);
zt_s32 zt_mcu_check_tx_buff(nic_info_st *nic_info);
zt_s32 zt_mcu_disable_fw_dbginfo(nic_info_st *pnic_info);

zt_s32 zt_mcu_set_macaddr(nic_info_st *nic_info, zt_u8 *val);
zt_s32 zt_mcu_get_chip_version(nic_info_st *nic_info, zt_u32 *version);
zt_s32 zt_mcu_set_op_mode(nic_info_st *nic_info, zt_u32 mode);
zt_s32 zt_mcu_set_hw_invalid_all(nic_info_st *nic_info);
zt_s32 zt_mcu_set_ch_bw(nic_info_st *nic_info, zt_u32 *args, zt_u32 arg_len);
zt_s32 zt_mcu_get_ch_bw(nic_info_st *nic_info, zt_u8 *channel,
                        CHANNEL_WIDTH *cw,
                        HAL_PRIME_CH_OFFSET *offset);
zt_s32 zt_mcu_set_hw_reg(nic_info_st *nic_info, zt_u32 *value, zt_u32 len);
zt_s32 zt_mcu_set_config_xmit(nic_info_st *nic_info, zt_s32 event, zt_u32 val);
zt_s32 zt_mcu_set_user_info(nic_info_st *nic_info, zt_bool state);
zt_s32 zt_mcu_set_mlme_scan(nic_info_st *nic_info, zt_bool enable);
zt_s32 zt_mcu_set_mlme_join(nic_info_st *nic_info, zt_u8 type);
zt_s32 zt_mcu_set_bssid(nic_info_st *nic_info, zt_u8 *bssid);
zt_s32 zt_mcu_set_sifs(nic_info_st *nic_info);
zt_s32 zt_mcu_set_macid_wakeup(nic_info_st *nic_info, zt_u32 wdn_id);
zt_s32 zt_mcu_set_basic_rate(nic_info_st *nic_info, zt_u16 br_cfg);
zt_s32 zt_mcu_set_preamble(nic_info_st *nic_info, zt_u8 short_val);
zt_s32 zt_mcu_set_slot_time(nic_info_st *nic_info, zt_u32 slotTime);
zt_s32 zt_mcu_set_media_status(nic_info_st *nic_info, zt_u32 status);
zt_s32 zt_mcu_set_bcn_intv(nic_info_st *nic_info, zt_u16 val);
zt_s32 zt_mcu_set_wmm_para_enable(nic_info_st *nic_info,
                                  wdn_net_info_st *wdn_info);
zt_s32 zt_mcu_set_wmm_para_disable(nic_info_st *nic_info,
                                   wdn_net_info_st *wdn_info);
zt_s32 zt_mcu_set_correct_tsf(nic_info_st *nic_info, zt_u64 tsf);
zt_s32 zt_mcu_set_on_rcr_am(nic_info_st *nic_info, zt_bool var_on);
zt_s32 zt_mcu_set_dk_cfg(nic_info_st *nic_info, zt_u32 auth_algrthm,
                         zt_bool dk_en);
zt_s32 zt_mcu_set_sec_cfg(nic_info_st *nic_info, zt_u8 val);
zt_s32 zt_mcu_set_sec_cam(nic_info_st *nic_info, struct cam_param *pcam_param);
zt_s32 zt_mcu_set_min_ampdu_space(nic_info_st *pnic_info, zt_u8 min_space);
zt_s32 zt_mcu_set_max_ampdu_len(nic_info_st *pnic_info, zt_u8 max_len);
zt_s32 zt_mcu_set_ac_vo(nic_info_st *pnic_info);
zt_s32 zt_mcu_set_ac_vi(nic_info_st *pnic_info);
zt_s32 zt_mcu_set_ac_be(nic_info_st *pnic_info);
zt_s32 zt_mcu_set_ac_bk(nic_info_st *pnic_info);
zt_s32 zt_mcu_get_bcn_valid(nic_info_st *pnic_info, zt_u32 *val32);
zt_s32 zt_mcu_set_bcn_valid(nic_info_st *pnic_info);
zt_s32 zt_mcu_set_bcn_sel(nic_info_st *pnic_info);
zt_s32 zt_mcu_update_thermal(nic_info_st *nic_info);

zt_s32 zt_mcu_handle_rf_iq_calibrate(nic_info_st *nic_info, zt_u8 channel);

zt_s32 zt_mcu_msg_body_get(nic_info_st *nic_info, mcu_msg_body_st *mcu_msg);
zt_s32 zt_mcu_msg_body_set(nic_info_st *nic_info, mcu_msg_body_st *mcu_msg);
zt_s32 zt_mcu_msg_body_sync(nic_info_st *nic_info, MSG_BODY_VARIABLE ops,
                            zt_u32 val);
zt_s32 zt_mcu_msg_sta_info_set(nic_info_st *nic_info,
                               mcu_msg_sta_info_st *msg_sta);
zt_s32 zt_mcu_rate_table_update(nic_info_st *nic_info,
                                wdn_net_info_st *wdn_net_info);
zt_s32 zt_mcu_hw_init(nic_info_st *nic_info, hw_param_st *param);
zt_s32 zt_mcu_ars_init(nic_info_st *nic_info);
zt_s32 zt_mcu_reset_chip(nic_info_st *nic_info);
zt_s32 zt_mcu_set_agg_param(nic_info_st *nic_info, zt_u32 agg_size,
                            zt_u32 agg_timeout, zt_u32 agg_dma_enable);
zt_s32 zt_mcu_ars_get_dbg_info(nic_info_st *nic_info, zt_u32 *info,
                               zt_u32 info_len);
zt_s32 zt_mcu_ars_set_dbg_info(nic_info_st *nic_info, zt_u32 *info,
                               zt_u32 info_len);

zt_s32 zt_mcu_ars_switch(nic_info_st *nic_info, zt_u32 open);

#ifdef CONFIG_LPS
zt_s32 zt_mcu_set_lps_opt(nic_info_st *pnic_info, zt_u32 data);
zt_s32 zt_mcu_set_lps_config(nic_info_st *nic_info);
zt_s32 zt_mcu_set_fw_lps_config(nic_info_st *pnic_info);
zt_s32 zt_mcu_set_fw_lps_get(nic_info_st *pnic_info);
zt_s32 zt_mcu_set_rsvd_page_loc(nic_info_st *nic_info, void *rsvdpage);
#endif

#ifdef CFG_ENABLE_AP_MODE
zt_s32 zt_mcu_set_ap_mode(nic_info_st *pnic_info);
zt_s32 zt_ap_connect_media_status(nic_info_st *pnic_info,
                                  wdn_net_info_st *pwdn_info);
zt_s32 zt_ap_disconnect_media_status(nic_info_st *pnic_info,
                                     wdn_net_info_st *pwdn_info);
#endif

#ifdef CFG_ENABLE_ADHOC_MODE
zt_s32 zt_adhoc_connect_media_status(nic_info_st *pnic_info,
                                     wdn_net_info_st *pwdn_info);
zt_s32 zt_adhoc_disconnect_media_status(nic_info_st *pnic_info,
                                        wdn_net_info_st *pwdn_info);
#endif


#endif

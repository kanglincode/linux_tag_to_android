################################################################################
################################################################################
##
## Makefile -- project specific makefile to build SCI Wifi driver
##
## (C) Copyright 2018-2020 by Suzhou WF Chip Semiconductor Co., LTD
##
## Mandatory settings:
##
## o TOPDIR                        = the toplevel directory (using slashes as path separator)
## o SUBDIR                        = the make file folder
## o CT                            = display driver compile time(y)
## o CONFIG_DRIVER_VER             = null(use svn version), else this is version
## o CONFIG_DBG_LEVEL              = 0x0F    One bit represents one debug level
## o CONFIG_DBG_COLOR              = Debug info display font color(y)
## o CONFIG_WIFI_INTERFACE_TWO     = Second WiFi interface (y)
## o CONFIG_TX_SOFT_AGG            = switch for tx soft agg(n)
## o CONFIG_RX_SOFT_AGG            = switch for rx soft agg(y)
## o CONFIG_WIFI_MODE              = all(sta/ap/adhoc/monitor), sta, ap, adhoc
## o CONFIG_WIFI_FRAMEWORK         = wext, nl80211
## o CONFIG_HIF_PORT               = usb, sdio, both
## o CONFIG_CHIP                   = ZT9101xV20
################################################################################
  export WDRV_DIR ?= $(shell pwd)
  SUBDIR = mak
  PLATDIR = platform
  CT                       ?= n
  CONFIG_DRIVER_VER         = null
  CONFIG_DBG_LEVEL          = 0x0F
  CONFIG_DBG_COLOR          = y
  CONFIG_STA_AND_AP_MODE    = y
  CONFIG_TX_SOFT_AGG        = y
  CONFIG_RX_SOFT_AGG        = y
  CONFIG_WIFI_MODE          = all
  CONFIG_WIFI_FRAMEWORK     = nl80211
  CONFIG_HIF_PORT           = usb
  CONFIG_CHIP               = ZT9101xV20
  CONFIG_POWER_SAVING       = n

include $(WDRV_DIR)/$(PLATDIR)/platform.mak

include $(WDRV_DIR)/$(SUBDIR)/linux/Makefile



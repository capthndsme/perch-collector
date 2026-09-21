#
# perch-collector: the Perch Network Collector. Passive per-device traffic
# accounting and protocol classification on the router, reported to the
# Perch Network Controller over a WebSocket the router dials (or polled).
#
# Use as a feed:  src-link perch /path/to/perch-collector/openwrt
#   ./scripts/feeds update perch && ./scripts/feeds install perch-collector
#   make menuconfig   # Network → perch-collector (nDPI on by default)
#   make package/perch-collector/compile
#
include $(TOPDIR)/rules.mk

PKG_NAME:=perch-collector
PKG_VERSION:=0.2.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/capthndsme/perch-collector/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=skip
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=capthndsme <nieoy@msn.com>

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/capthndsme/perch-collector
GO_PKG_LDFLAGS:=-s -w
GO_PKG_LDFLAGS_X:=main.version=$(PKG_VERSION)
GO_PKG_INSTALL_BIN_PATH:=/usr/bin
ifeq ($(CONFIG_PERCH_COLLECTOR_NDPI),y)
GO_PKG_TAGS:=ndpi
endif

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/perch-collector
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Network Monitoring
  TITLE:=Perch Network Collector
  URL:=https://github.com/capthndsme/perch-collector
  DEPENDS:=$(GO_ARCH_DEPENDS) +libpcap +PERCH_COLLECTOR_NDPI:libndpi
endef

define Package/perch-collector/description
  Passive per-device traffic accounting for Perch: bytes per MAC, protocol
  and application classification (nDPI, optional), top peers, server names
  and destinations, plus the router's own health (connection tracking, WAN
  rate, load) for the controller's Gateway page. Captures on the LAN
  bridge, keeps everything in memory and pushes it to the Perch Network
  Controller over a WebSocket the router dials, so nothing has to reach
  the router. Configured through UCI (/etc/config/perch-collector); the API
  key and the instance id are generated on first start.
endef

define Package/perch-collector/config
  config PERCH_COLLECTOR_NDPI
    bool "Deep packet inspection with libndpi (application classification)"
    depends on PACKAGE_perch-collector
    default y
    help
      Without it flows are labelled by port only. nDPI costs CPU on small
      routers; a MT7621-class device should start with it off.
endef

define Package/perch-collector/conffiles
/etc/config/perch-collector
endef

define Package/perch-collector/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/perch-collector $(1)/usr/bin/perch-collector
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/perch-collector.init $(1)/etc/init.d/perch-collector
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/perch-collector.config $(1)/etc/config/perch-collector
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/perch-collector.defaults $(1)/etc/uci-defaults/90-perch-collector
endef

$(eval $(call GoBinPackage,perch-collector))
$(eval $(call BuildPackage,perch-collector))

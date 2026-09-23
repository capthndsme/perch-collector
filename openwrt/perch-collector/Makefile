#
# perch-collector: the Perch Network Collector. Passive per-device traffic
# accounting and protocol classification on the router, reported to the
# Perch Network Controller over a WebSocket the router dials (or polled).
#
# Use as a feed:  src-link perch /path/to/perch-collector/openwrt
#   ./scripts/feeds update perch && ./scripts/feeds install perch-collector
#   make package/perch-collector/compile
# or from a checkout, with Docker: scripts/openwrt-package.sh <arch> <release>
#
# nDPI 5.0 is built from source and linked statically: the collector binds
# the nDPI 5.0 API only, whatever libndpi the packages feed carries. The
# package therefore needs only libpcap at runtime.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=perch-collector
PKG_VERSION:=1.0.0_rc1
PKG_RELEASE:=1
# PKG_VERSION is in the form both opkg and apk-tools accept: a pre-release is
# 1.0.0_rc1 (apk rejects 1.0.0-rc.1). PERCH_VERSION is the upstream version,
# which names the git tag (v1.0.0-rc.1) and is what --version prints.
PERCH_VERSION:=$(subst _alpha,-alpha.,$(subst _beta,-beta.,$(subst _rc,-rc.,$(subst _pre,-pre.,$(PKG_VERSION)))))

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/capthndsme/perch-collector/tar.gz/v$(PERCH_VERSION)?
PKG_HASH:=skip
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

NDPI_VERSION:=5.0
NDPI_FILE:=nDPI-$(NDPI_VERSION).tar.gz
NDPI_HASH:=8b0d3dc0c8a6a68578e09a18c922021ef6458d4aca1c7a20ce04efc267aa9ea5

PKG_LICENSE:=MIT LGPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=capthndsme <nieoy@msn.com>

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/capthndsme/perch-collector
GO_PKG_BUILD_PKG:=$(GO_PKG)
GO_PKG_LDFLAGS:=-s -w
GO_PKG_LDFLAGS_X:=main.version=$(PERCH_VERSION)
GO_PKG_TAGS:=ndpi
GO_PKG_INSTALL_BIN_PATH:=/usr/bin

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

# Under a directory starting with "_", which the Go tooling never descends into.
NDPI_SRC:=$(PKG_BUILD_DIR)/_ndpi/nDPI-$(NDPI_VERSION)
NDPI_STAGE:=$(PKG_BUILD_DIR)/_ndpi/stage

# cgo finds libndpi through this .pc file. Absolute paths on purpose: the
# SDK's pkg-config wrapper redefines ${prefix} to the target staging dir.
GO_PKG_BUILD_VARS+=PKG_CONFIG_PATH=$(NDPI_STAGE)/lib/pkgconfig

define Download/ndpi
  URL:=https://codeload.github.com/ntop/nDPI/tar.gz/refs/tags/$(NDPI_VERSION)?
  URL_FILE:=
  FILE:=$(NDPI_FILE)
  HASH:=$(NDPI_HASH)
endef
$(eval $(call Download,ndpi))

define Package/perch-collector
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Network Monitoring
  TITLE:=Perch Network Collector
  URL:=https://github.com/capthndsme/perch-collector
  DEPENDS:=$(GO_ARCH_DEPENDS) +libpcap
endef

define Package/perch-collector/description
  Passive per-device traffic accounting for Perch: bytes per MAC, protocol
  and application classification (nDPI 5.0, linked in), top peers, server
  names and destinations, plus the router's own health (connection
  tracking, WAN rate, load) for the controller's Gateway page. Captures on
  the LAN bridge, keeps everything in memory and pushes it to the Perch
  Network Controller over a WebSocket the router dials, so nothing has to
  reach the router. Configured through UCI (/etc/config/perch-collector);
  the API key and the instance id are generated on first start. On a small
  router, option classification 'port' turns deep packet inspection off.
endef

define Package/perch-collector/conffiles
/etc/config/perch-collector
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/_ndpi
	$(TAR) -C $(PKG_BUILD_DIR)/_ndpi -xzf $(DL_DIR)/$(NDPI_FILE)
endef

# nDPI 5.0's autogen.sh only runs autoreconf; configure with the target
# toolchain, then build the static library alone (no libndpi.so to pick up).
define Build/Configure
	cd $(NDPI_SRC) && autoreconf -ivf >/dev/null
	$(call Build/Configure/Default,--with-only-libndpi,,_ndpi/nDPI-$(NDPI_VERSION))
	$(call GoPackage/Build/Configure)
endef

define Build/Compile
	$(MAKE) $(PKG_JOBS) -C $(NDPI_SRC)/src/lib libndpi.a
	rm -rf $(NDPI_STAGE)
	$(INSTALL_DIR) $(NDPI_STAGE)/lib/pkgconfig $(NDPI_STAGE)/include/ndpi
	$(CP) $(NDPI_SRC)/src/lib/libndpi.a $(NDPI_STAGE)/lib/
	find $(NDPI_SRC)/src/include -maxdepth 1 -name '*.h' ! -name ndpi_private.h \
		-exec $(CP) {} $(NDPI_STAGE)/include/ndpi/ \;
	printf '%s\n' \
		'Name: libndpi' \
		'Description: nDPI $(NDPI_VERSION), static, private to perch-collector' \
		'Version: $(NDPI_VERSION).0' \
		'Libs: $(NDPI_STAGE)/lib/libndpi.a -lm' \
		'Cflags: -I$(NDPI_STAGE)/include/ndpi' \
		> $(NDPI_STAGE)/lib/pkgconfig/libndpi.pc
	$(call GoPackage/Build/Compile)
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

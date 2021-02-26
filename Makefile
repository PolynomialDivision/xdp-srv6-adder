include $(TOPDIR)/rules.mk

PKG_NAME:=xdp-srv6-adder
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0+
PKG_LICENSE_FILES:=

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/xdp-srv6-adder
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libubox +libbpf +libnl-tiny
  TITLE:=XDP SRv6 Adder
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include \
	-I$(STAGING_DIR)/usr/include/libnl-tiny

ifeq ($(CONFIG_BIG_ENDIAN),y)
export BPF_TARGET=bpfeb
else
export BPF_TARGET=bpfel
endif

define Package/xdp-srv6-adder/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xdp-srv6-adder $(1)/sbin/
	$(INSTALL_DIR) $(1)/usr/xdp/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/srv6_add_kern.o $(1)/usr/xdp/srv6_add_kern.o
endef

$(eval $(call BuildPackage,xdp-srv6-adder))

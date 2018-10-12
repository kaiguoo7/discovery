
include $(TOPDIR)/rules.mk
PKG_VERSION:=1.0.0
PKG_RELEASE:=1.0.0

PKG_NAME:=discovery
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  CATEGORY:=Ruijie modules
  SUBMENU:=Cloud management modules
  TITLE:=discovery module
  DEPENDS:= +libubus +libubox +libdebug +libjson-c +libpthread +libuci +ubus
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)	
	$(CP) -r ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/ CC="$(TARGET_CC)" CROSS_COMPILE="$(TARGET_CROSS)"
endef

define Package/$(PKG_NAME)/preinst
#!/bin/sh
if [ -f /etc/init.d/discovery ]; then
/etc/init.d/discovery stop
fi
exit 0
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
/etc/init.d/discovery start
exit 0
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME).elf $(1)/usr/sbin/
	
	$(INSTALL_DIR) $(1)/etc/init.d/
	chmod +x $(PKG_BUILD_DIR)/etc/init.d/$(PKG_NAME)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/init.d/$(PKG_NAME) $(1)/etc/init.d/$(PKG_NAME)
	
	$(INSTALL_DIR) $(1)/etc/config/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/config/* $(1)/etc/config/
	
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/script/usr/bin/* $(1)/usr/bin/
	
	$(INSTALL_DIR) $(1)/lib/discovery/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/script/lib/discovery/* $(1)/lib/discovery/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))     


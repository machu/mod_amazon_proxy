mod_amazon_proxy.la: mod_amazon_proxy.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_amazon_proxy.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_amazon_proxy.la

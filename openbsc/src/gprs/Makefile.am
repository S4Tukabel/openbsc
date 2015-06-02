NWEPC_CFLAGS = -DNW_LOG_TO_FILE\
	-I$(top_srcdir)/nw-gtpv2c/include\
	-I$(top_srcdir)/nw-gtpv2c/shared\
	-I$(top_srcdir)/nw-gtpv1u/include\
	-I$(top_srcdir)/nw-gtpv1u/shared\
	-I$(top_srcdir)/nw-sdp/shared\
	-I$(top_srcdir)/common\
	-I$(top_srcdir)/include\
	-I$(top_srcdir)/utils/nw-ipv4-if\
	-I$(top_srcdir)/utils/nw-gtpv2c-if\
	-I$(top_srcdir)/utils/nw-gtpu-if\
	-I$(top_srcdir)/utils/nw-log\
	-I$(top_srcdir)/utils/nw-tmr\
	-I$(top_srcdir)/utils/nw-ippool\
	-I$(top_srcdir)/nw-event/include\
	-I$(top_srcdir)/nw-sae-gw
	
	
AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall -fno-strict-aliasing $(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) $(LIBOSMOGB_CFLAGS) $(COVERAGE_CFLAGS)\
	$(NWEPC_CFLAGS) #$(LIBNWGTPV2C_CFLAGS)
	
OSMO_LIBS = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) \
	    $(LIBOSMOCTRL_LIBS) $(LIBOSMOGB_LIBS) #$(LIBNWGTPV2C_LIBS)

# TUKABELS
LIBNWGTPV2C_CFLAGS = -I/usr/local/include/ 
LIBNWGTPV2C_LIBS = -L/usr/local/lib -lNwGtpv2c

noinst_HEADERS = gprs_sndcp.h

if HAVE_LIBGTP
bin_PROGRAMS = osmo-gbproxy osmo-sgsn
else
bin_PROGRAMS = osmo-gbproxy
endif

osmo_gbproxy_SOURCES =  gb_proxy.c gb_proxy_main.c gb_proxy_vty.c \
			gb_proxy_patch.c gb_proxy_tlli.c gb_proxy_peer.c \
			gprs_gb_parse.c gprs_llc_parse.c crc24.c gprs_utils.c
osmo_gbproxy_LDADD = 	$(top_builddir)/src/libcommon/libcommon.a \
			$(OSMO_LIBS) -lrt -levent 
	
NWEPC_SOURCES =		\
                        ../../common/tree.h\
                        ../../common/queue.h\
                        ../../common/NwTypes.h\
                        ../../common/NwError.h\
                        ../../common/NwLog.h\
                        ../../common/NwUtils.h\
                        ../../common/NwMem.h\
                        ../../common/NwEvt.h\
                        ../../utils/nw-tmr/NwTmrMgr.h\
                        ../../utils/nw-log/NwLogMgr.h\
                        ../../utils/nw-ipv4-if/NwIpv4IfLog.h\
                        ../../utils/nw-ipv4-if/NwIpv4If.h\
                        ../../utils/nw-gtpv2c-if/NwGtpv2cIfLog.h\
                        ../../utils/nw-gtpv2c-if/NwGtpv2cIf.h\
                        ../../utils/nw-gtpu-if/NwGtpv1uIfLog.h\
                        ../../utils/nw-gtpu-if/NwGtpv1uIf.h\
                        ../../utils/nw-ippool/NwIpv4PoolMgr.h\
                        ../../utils/nw-ippool/NwIpv4PoolMgrLog.h\
                        ../../utils/nw-tmr/NwTmrMgr.c\
                        ../../utils/nw-log/NwLogMgr.c\
                        ../../utils/nw-ipv4-if/NwIpv4If.c\
                        ../../utils/nw-gtpv2c-if/NwGtpv2cIf.c\
                        ../../utils/nw-gtpu-if/NwGtpv1uIf.c\
                        ../../utils/nw-ippool/NwIpv4PoolMgr.c\
                        ../../nw-gtpv2c/shared/NwGtpv2c.h\
                        ../../nw-gtpv2c/shared/NwGtpv2cIe.h\
                        ../../nw-gtpv2c/shared/NwGtpv2cMsg.h\
                        ../../nw-gtpv2c/shared/NwGtpv2cMsgParser.h\
                        ../../nw-gtpv1u/shared/NwGtpv1u.h\
			../../nw-sdp/shared/NwSdp.h\
                        ../../common/NwMem.c

osmo_sgsn_SOURCES =	gprs_gmm.c gprs_sgsn.c gprs_sndcp.c gprs_sndcp_vty.c \
			sgsn_main.c sgsn_vty.c sgsn_libgtp.c \
			gprs_llc.c gprs_llc_parse.c gprs_llc_vty.c crc24.c \
			sgsn_ctrl.c sgsn_auth.c gprs_subscriber.c \
			gprs_gsup_messages.c gprs_utils.c gprs_gsup_client.c \
			gsm_04_08_gprs.c sgsn_cdr.c sgsn_s4.c \
			NwMiniLogMgrEntity.c NwMiniTmrMgrEntity.c \
			NwMiniUlpEntity.c NwMiniUdpEntity.c\
			$(NWEPC_SOURCES)


NWEPC_LDADD =		\
			$(top_builddir)/nw-gtpv2c/src/libNwGtpv2c.a\
			$(top_builddir)/nw-sdp/src/libNwSdp.a\
			$(top_builddir)/nw-gtpv1u/src/libNwGtpv1u.a\
			$(top_builddir)/nw-gre/src/libNwGre.a\
			$(top_builddir)/nw-ipv4/src/libNwIpv4.a\
			$(top_builddir)/nw-event/src/libNwEvent.a
	
osmo_sgsn_LDADD = 	\
			$(top_builddir)/src/libcommon/libcommon.a \
			-lgtp $(OSMO_LIBS) $(LIBOSMOABIS_LIBS) -lrt -levent -lgtp\
			$(NWEPC_LDADD)



# this is example-file: src/bin/Makefile.am


# path to nwEpc
nwEpc_PATH = ../../../../nwEPC

# nwEpc makefile
SUBDIRS = $(nwEpc_PATH)


# additional include paths necessary to compile the C++ programs
AM_CFLAGS = -DNW_LOG_TO_FILE -Wall -I/usr/local/include/ -I/usr/local/include/mylib/ \
	-I$(nwEpc_PATH)/common/ -I$(nwEpc_PATH)/nw-event/include/ -I$(nwEpc_PATH)/utils/nw-gtpv2c-if/ \
	-I$(nwEpc_PATH)/utils/nw-gtpv2c-if/ -I$(nwEpc_PATH)/utils/nw-gtpu-if/  \
	-I$(nwEpc_PATH)/utils/nw-ippool/ -I$(nwEpc_PATH)/utils/nw-log/ \
	-I$(nwEpc_PATH)/nw-sdp/shared/ \
	@AM_CFLAGS@

#-I$(top_srcdir)/nw-gtpv2c/shared -I$(top_srcdir)/nw-gtpv1u/shared -I$(top_srcdir)/nw-sdp/shared -I$(top_srcdir)/common -I$(top_srcdir)/include -I$(top_srcdir)/utils/nw-ipv4-if -I$(top_srcdir)/utils/nw-gtpv2c-if -I$(top_srcdir)/utils/nw-gtpu-if  -I$(top_srcdir)/utils/nw-log -I$(top_srcdir)/utils/nw-tmr -I$(top_srcdir)/utils/nw-ippool -I$(top_srcdir)/nw-event/include

bin_PROGRAMS = nwLteSaeGw


# list of sources for the 'NwWimaxBsEmu' binary
nwLteSaeGw_SOURCES =    \
                        $(nwEpc_PATH)/common/tree.h\
                        $(nwEpc_PATH)/common/NwMem.h\
                        $(nwEpc_PATH)/common/NwEvt.h\
                        $(nwEpc_PATH)/utils/nw-tmr/NwTmrMgr.h\
                        $(nwEpc_PATH)/utils/nw-ipv4-if/NwIpv4IfLog.h\
                        $(nwEpc_PATH)/utils/nw-ipv4-if/NwIpv4If.h\
                        $(nwEpc_PATH)/utils/nw-gtpv2c-if/NwGtpv2cIfLog.h\
                        $(nwEpc_PATH)/utils/nw-gtpv2c-if/NwGtpv2cIf.h\
                        $(nwEpc_PATH)/utils/nw-gtpu-if/NwGtpv1uIfLog.h\
                        $(nwEpc_PATH)/utils/nw-gtpu-if/NwGtpv1uIf.h\
                        $(nwEpc_PATH)/utils/nw-ippool/NwIpv4PoolMgr.h\
                        $(nwEpc_PATH)/utils/nw-ippool/NwIpv4PoolMgrLog.h\
                        $(nwEpc_PATH)/utils/nw-tmr/NwTmrMgr.c\
                        $(nwEpc_PATH)/utils/nw-log/NwLogMgr.c\
                        $(nwEpc_PATH)/utils/nw-ipv4-if/NwIpv4If.c\
                        $(nwEpc_PATH)/utils/nw-gtpv2c-if/NwGtpv2cIf.c\
                        $(nwEpc_PATH)/utils/nw-gtpu-if/NwGtpv1uIf.c\
                        $(nwEpc_PATH)/utils/nw-ippool/NwIpv4PoolMgr.c
			$(nwEpc_PATH)/nw-sdp/shared/NwSdp.h\
                        $(nwEpc_PATH)/common/NwMem.c\
                        NwSaeGwLog.h\
                        NwSaeGwUeLog.h\
			NwSaeGwUlp.h\
			NwSaeGwDpe.h\
                        NwSaeGwUe.h\
                        NwSaeGwUeFsm.h\
                        NwSaeGwUeState.h\
                        NwSaeGwUeStateInit.h\
                        NwSaeGwUeStateSaeSessionCreated.h\
                        NwSaeGwUeStateSgwSessionCreated.h\
                        NwSaeGwUeStatePgwSessionCreated.h\
                        NwSaeGwUeStateSaeSessionEstablished.h\
                        NwSaeGwUeStateSgwSessionEstablished.h\
                        NwSaeGwUeStateAwaitPgwCreateSessionRsp.h\
                        NwSaeGwUeStateAwaitPgwDeleteSessionRsp.h\
                        NwSaeGwUeStateAwaitPgwModifyBearerRsp.h\
                        NwSaeGwUeStateAwaitPgwModifyBearerRsp2.h\
			NwSaeGwUlp.c\
			NwSaeGwDpe.c\
                        NwSaeGwUeFsm.c\
                        NwSaeGwUeState.c\
                        NwSaeGwUeStateInit.c\
                        NwSaeGwUeStateSaeSessionCreated.c\
                        NwSaeGwUeStateSgwSessionCreated.c\
                        NwSaeGwUeStatePgwSessionCreated.c\
                        NwSaeGwUeStateSaeSessionEstablished.c\
                        NwSaeGwUeStateSgwSessionEstablished.c\
                        NwSaeGwUeStateAwaitPgwCreateSessionRsp.c\
                        NwSaeGwUeStateAwaitPgwDeleteSessionRsp.c\
                        NwSaeGwUeStateAwaitPgwModifyBearerRsp.c\
                        NwSaeGwUeStateAwaitPgwModifyBearerRsp2.c\
                        NwSaeGwMain.c\
                        NwSaeGwUe.c

#                        ../nw-gtpv2c/shared/NwGtpv2c.h\
#                        ../nw-gtpv2c/shared/NwGtpv2cIe.h\
#                        ../nw-gtpv2c/shared/NwGtpv2cMsg.h\
#                        ../nw-gtpv2c/shared/NwGtpv2cMsgParser.h\
#                        ../nw-gtpv1u/shared/NwGtpv1u.h\
#                        ../common/queue.h\
#                        ../common/NwTypes.h\
#                        ../common/NwError.h\
#                        ../common/NwLog.h\
#                        ../common/NwUtils.h\
#                        ../utils/nw-log/NwLogMgr.h\
#

# the additional libraries needed to link nwWimaxBsEmu 
#nwLteSaeGw_LDADD =  $(top_builddir)/nw-gtpv2c/src/libNwGtpv2c.a $(top_builddir)/nw-sdp/src/libNwSdp.a $(top_builddir)/nw-gtpv1u/src/libNwGtpv1u.a $(top_builddir)/nw-gre/src/libNwGre.a  $(top_builddir)/nw-ipv4/src/libNwIpv4.a $(top_builddir)/nw-event/src/libNwEvent.a  $(AM_LDFLAGS)

nwLteSaeGw_LDADD = -lNwGtpv2c -lNwSdp -lNwGtpv1u -lNwGre -lNwIpv4 -lNwEvent $(AM_LDFLAGS)

#nwLteSaeGw_LDADD = libNwGtpv2c.a libNwSdp.a libNwGtpv1u.a libNwGre.a libNwIpv4.a libNwEvent.a $(AM_LDFLAGS)

###############################################################################

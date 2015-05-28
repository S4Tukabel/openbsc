#define __WITH_LIBEVENT__

#include <openbsc/sgsn_s4.h>

#include <stdio.h>
#include <assert.h>
#include <signal.h>

#include "NwEvt.h"
#include <mylib/NwLog.h>
#include <mylib/NwGtpv2c.h>
#include "NwMiniLogMgrEntity.h"
#include "NwMiniTmrMgrEntity.h"
#include "NwMiniUdpEntity.h"
#include "NwMiniUlpEntity.h"

#include <mylib/NwTypes.h>
#include <mylib/NwError.h>
#include <mylib/NwUtils.h>
//#include <mylib/NwLogMgr.h>
//#include <mylib/NwSaeGwUeLog.h>
//#include <mylib/NwSaeGwUeState.h>
#include <mylib/NwGtpv2cIe.h>
#include <mylib/NwGtpv2cMsg.h>

//#include <mylib/NwSaeGwUlp.h>


static NwGtpv2cNodeUlpT              ulpObj;
static NwGtpv2cNodeUdpT              udpObj;

 /* 29.274 IMSI, MSISDN - appedn with 1 bits*/
static void imsi_str2arr(char *str, NwU8T *imsi)
{
	//uint64_t imsi64 = 0;
	unsigned int n;
	unsigned int imsi_len = strlen(str);

        /*
	if (imsi_len > 16) {
		LOGP(DGPRS, LOGL_NOTICE, "IMSI length > 16 not supported!\n");
		return 0;
	}
         */

       
	for (n = 0; n < 16; n += 2) {
		NwU8T val;
		if (n < imsi_len)
			val = (str[n]-'0') & 0xf;
		else
			val = 0xf;
                if (n + 1 < imsi_len)
                    val = (val << 4) | ((str[n + 1]-'0') & 0xf);
                else
                    val = (val << 4) | 0xf;
                
                imsi[n / 2] = val;
	}
}

NwRcT
sgsn_s4_send_create_session_request(NwSaeGwUeT* thiz, /*NwGtpv2cUlpTrxnHandleT hTrxn, */ struct sgsn_mm_ctx *mmctx) 
{
  NwRcT rc;
  NwGtpv2cUlpApiT       ulpReq;
  NwU8T imsi[8];
  NwU8T msisdn[8];
  NwU8T mei[8];
  NwU8T service_network[3];
  NwSaeGwPaaT paa;

  rc = nwGtpv2cMsgNew( thiz->hGtpv2cStackSgwS5,
      NW_TRUE,                                          /* TIED present*/
      NW_GTP_CREATE_SESSION_REQ,                        /* Msg Type    */
      0,                                                /* TEID        */
      0,                                                /* Seq Number  */
      &(ulpReq.hMsg));

  NW_ASSERT( NW_OK == rc );
  
  imsi_str2arr(mmctx->imsi, imsi);
  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_IMSI, 8, 0, imsi);
  NW_ASSERT( NW_OK == rc );

  imsi_str2arr(mmctx->msisdn, msisdn);
  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_MSISDN, 8, 0, msisdn);thiz
  NW_ASSERT( NW_OK == rc );

  imsi_str2arr(mmctx->imei, mei);
  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_MEI, 8, 0, mei);
  NW_ASSERT( NW_OK == rc );

  /* 2 = GAN*/
  rc = nwGtpv2cMsgAddIeTV1((ulpReq.hMsg), NW_GTPV2C_IE_RAT_TYPE, 0, 4);
  NW_ASSERT( NW_OK == rc );

  /* Service NW = MCC + MNC (part of imsi)*/
  memcpy(service_network, imsi, 3);
  service_network[2] |= 0xf0;
  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_SERVING_NETWORK, 3, 0, service_network);
  NW_ASSERT( NW_OK == rc );

  // NW_GTPV2C_IFTYPE_S4_SGSN_GTPC = 17
  // TODO: IPv4
  rc = nwGtpv2cMsgAddIeFteid((ulpReq.hMsg), NW_GTPV2C_IE_INSTANCE_ZERO, 17, (NwU32T)mmctx, thiz->s5s8cTunnel.fteidSgw.ipv4Addr, NULL);
  NW_ASSERT( NW_OK == rc );

  rc = nwGtpv2cMsgAddIeTV1((ulpReq.hMsg), NW_GTPV2C_IE_SELECTION_MODE, 0, 0x02);
  NW_ASSERT( NW_OK == rc );

  rc = nwGtpv2cMsgAddIeTV1((ulpReq.hMsg), NW_GTPV2C_IE_PDN_TYPE, 0, NW_PDN_TYPE_IPv4);
  NW_ASSERT( NW_OK == rc );

  paa.pdnType = NW_PDN_TYPE_IPv4;
  // TODO: ipv4Addr
  paa.ipv4Addr[0] = 0x00;
  paa.ipv4Addr[1] = 0x00;
  paa.ipv4Addr[2] = 0x00;
  paa.ipv4Addr[3] = 0x00;
  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_PAA, sizeof(paa), 0, (NwU8T*)&paa);
  NW_ASSERT( NW_OK == rc );

  //// potade sme sa dotrepali
  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_APN, thiz->apn.l, NW_GTPV2C_IE_INSTANCE_ZERO, thiz->apn.v);
  NW_ASSERT( NW_OK == rc );

  rc = nwGtpv2cMsgAddIeTV1((ulpReq.hMsg), NW_GTPV2C_IE_APN_RESTRICTION, 0, thiz->apnRes);
  NW_ASSERT( NW_OK == rc );

  rc = nwGtpv2cMsgGroupedIeStart((ulpReq.hMsg), NW_GTPV2C_IE_BEARER_CONTEXT, 0);
  NW_ASSERT( NW_OK == rc );

  rc = nwGtpv2cMsgAddIeTV1((ulpReq.hMsg), NW_GTPV2C_IE_EBI, NW_GTPV2C_IE_INSTANCE_ZERO, 5);
  NW_ASSERT( NW_OK == rc );

  NW_ASSERT( thiz->epsBearer[5].s5s8uTunnel.fteidSgw.ipv4Addr != 0); //AMIT
  rc = nwGtpv2cMsgAddIeFteid((ulpReq.hMsg),
      NW_GTPV2C_IE_INSTANCE_TWO,
      NW_GTPV2C_IFTYPE_S5S8_SGW_GTPU,
      ((NwU32T)(thiz->epsBearer[5].s5s8uTunnel.fteidSgw.teidOrGreKey)),
      ((NwU32T)(thiz->epsBearer[5].s5s8uTunnel.fteidSgw.ipv4Addr)),
      NULL);
  NW_ASSERT( NW_OK == rc );

 
// pragma replaced with _attribute((packed))
//#pragma pack(1)
  struct __attribute__((packed)){
    NwU8T arp;
    NwU8T labelQci;
    NwU8T maximumBitRateUplink[5];
    NwU8T maximumBitRateDownlink[5];
    NwU8T  guaranteedBitRateUplink[5];
    NwU8T  guaranteedBitRateDownlink[5];
  } bearerQos;
//#pragma pack()

  bearerQos.arp                         = 0x01;
  bearerQos.labelQci                    = 0x01;

  memset(bearerQos.maximumBitRateUplink, 0x00,5);
  memset(bearerQos.maximumBitRateDownlink, 0x00,5);
  memset(bearerQos.guaranteedBitRateUplink, 0x00,5);
  memset(bearerQos.guaranteedBitRateDownlink, 0x00,5);


  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_BEARER_LEVEL_QOS, sizeof(bearerQos), 0, (NwU8T*)&bearerQos);
  NW_ASSERT( NW_OK == rc );


  rc = nwGtpv2cMsgGroupedIeEnd((ulpReq.hMsg));
  NW_ASSERT( NW_OK == rc );

  /* End - Encoding of grouped IE "bearer context created" */

  /* Send Create Session Request to PGW */

  ulpReq.apiType = (NW_GTPV2C_ULP_API_INITIAL_REQ | NW_GTPV2C_ULP_API_FLAG_CREATE_LOCAL_TUNNEL);

  ulpReq.apiInfo.initialReqInfo.hTunnel         = 0;                       
  ulpReq.apiInfo.initialReqInfo.hUlpTrxn        = 0; ///tukabel zero/// hTrxn;                        /* Save the trxn for Response */
  ulpReq.apiInfo.initialReqInfo.hUlpTunnel      = (NwGtpv2cUlpTrxnHandleT)thiz;
  ulpReq.apiInfo.initialReqInfo.teidLocal       = (NwGtpv2cUlpTrxnHandleT)thiz;
  ulpReq.apiInfo.initialReqInfo.peerIp          = htonl(thiz->s5s8cTunnel.fteidPgw.ipv4Addr);

  rc = nwGtpv2cProcessUlpReq(thiz->hGtpv2cStackSgwS5, &ulpReq);
  NW_ASSERT( NW_OK == rc );

  thiz->s5s8cTunnel.hSgwLocalTunnel = ulpReq.apiInfo.initialReqInfo.hTunnel;

  // TUKABEL TODO: log
  //NW_UE_LOG(NW_LOG_LEVEL_INFO, "Create Session Request sent to PGW "NW_IPV4_ADDR"!", NW_IPV4_ADDR_FORMAT(ulpReq.apiInfo.initialReqInfo.peerIp));

  return rc;
}


static void S4Initialize(NwU8T localIpStr[20], NwU8T targetIpStr[20])
{
  NwRcT                         rc; 
  NwU32T                        logLevel;
  NwU8T*                        logLevelStr;

  NwGtpv2cStackHandleT          hGtpv2cStack = 0;

  NwGtpv2cUlpEntityT            ulp;
  NwGtpv2cUdpEntityT            udp;
  NwGtpv2cTimerMgrEntityT       tmrMgr;
  NwGtpv2cLogMgrEntityT         logMgr;
  

  //logLevelStr = getenv ("NW_LOG_LEVEL");
  logLevelStr = "DEBG";

  if(logLevelStr == NULL)
  {
    logLevel = NW_LOG_LEVEL_INFO;
  }
  else
  {
    if(strncmp(logLevelStr, "EMER",4) == 0)
      logLevel = NW_LOG_LEVEL_EMER;
    else if(strncmp(logLevelStr, "ALER",4) == 0)
      logLevel = NW_LOG_LEVEL_ALER;
    else if(strncmp(logLevelStr, "CRIT",4) == 0)
      logLevel = NW_LOG_LEVEL_CRIT;
    else if(strncmp(logLevelStr, "ERRO",4) == 0)
      logLevel = NW_LOG_LEVEL_ERRO ;
    else if(strncmp(logLevelStr, "WARN",4) == 0)
      logLevel = NW_LOG_LEVEL_WARN;
    else if(strncmp(logLevelStr, "NOTI",4) == 0)
      logLevel = NW_LOG_LEVEL_NOTI;
    else if(strncmp(logLevelStr, "INFO",4) == 0)
      logLevel = NW_LOG_LEVEL_INFO;
    else if(strncmp(logLevelStr, "DEBG",4) == 0)
      logLevel = NW_LOG_LEVEL_DEBG;
  }

  /*---------------------------------------------------------------------------
   *  Initialize event library
   *--------------------------------------------------------------------------*/

  NW_EVT_INIT();

  /*---------------------------------------------------------------------------
   *  Initialize Log Manager 
   *--------------------------------------------------------------------------*/
  nwMiniLogMgrInit(nwMiniLogMgrGetInstance(), logLevel);

  /*---------------------------------------------------------------------------
   *  Initialize Gtpv2c Stack Instance
   *--------------------------------------------------------------------------*/
  rc = nwGtpv2cInitialize(&hGtpv2cStack);

  if(rc != NW_OK)
  {
    NW_LOG(NW_LOG_LEVEL_ERRO, "Failed to create gtpv2c stack instance. Error '%u' occured", rc);
    exit(1);
  }

  rc = nwGtpv2cSetLogLevel(hGtpv2cStack, logLevel);

  /*---------------------------------------------------------------------------
   * Set up Ulp Entity 
   *--------------------------------------------------------------------------*/
  rc = nwGtpv2cUlpInit(&ulpObj, hGtpv2cStack, localIpStr);
  NW_ASSERT(NW_OK == rc);

  ulp.hUlp = (NwGtpv2cUlpHandleT) &ulpObj;
  ulp.ulpReqCallback = nwGtpv2cUlpProcessStackReqCallback;

  rc = nwGtpv2cSetUlpEntity(hGtpv2cStack, &ulp);
  NW_ASSERT(NW_OK == rc);

  /*---------------------------------------------------------------------------
   * Set up Udp Entity 
   *--------------------------------------------------------------------------*/
  rc = nwGtpv2cUdpInit(&udpObj, hGtpv2cStack, localIpStr);
  NW_ASSERT(NW_OK == rc);

  udp.hUdp = (NwGtpv2cUdpHandleT) &udpObj;
  udp.udpDataReqCallback = nwGtpv2cUdpDataReq;

  rc = nwGtpv2cSetUdpEntity(hGtpv2cStack, &udp);
  NW_ASSERT(NW_OK == rc);

  /*---------------------------------------------------------------------------
   * Set up Log Entity 
   *--------------------------------------------------------------------------*/
  tmrMgr.tmrMgrHandle = 0;
  tmrMgr.tmrStartCallback = nwTimerStart;
  tmrMgr.tmrStopCallback = nwTimerStop;

  rc = nwGtpv2cSetTimerMgrEntity(hGtpv2cStack, &tmrMgr);
  NW_ASSERT(NW_OK == rc);

  /*---------------------------------------------------------------------------
   * Set up Log Entity 
   *--------------------------------------------------------------------------*/
  logMgr.logMgrHandle   = (NwGtpv2cLogMgrHandleT) nwMiniLogMgrGetInstance();
  logMgr.logReqCallback  = nwMiniLogMgrLogRequest;

  rc = nwGtpv2cSetLogMgrEntity(hGtpv2cStack, &logMgr);
  NW_ASSERT(NW_OK == rc);

  /*---------------------------------------------------------------------------
   *  Send Message Request to Gtpv2c Stack Instance
   *--------------------------------------------------------------------------*/
  NW_LOG(NW_LOG_LEVEL_NOTI, "EGTPING %s ("NW_IPV4_ADDR")", targetIpStr, NW_IPV4_ADDR_FORMAT(inet_addr(targetIpStr)));
  rc = nwGtpv2cUlpPing(&ulpObj, 
                        inet_addr(targetIpStr),
                        4,
                        10,
                        2,
                        3);
  NW_ASSERT(NW_OK == rc);

  /*---------------------------------------------------------------------------
   * Install signal handler 
   *--------------------------------------------------------------------------*/
  //signal(SIGINT, nwEgtPingHandleSignal);

  /*---------------------------------------------------------------------------
   * Event loop 
   *--------------------------------------------------------------------------*/

  NW_EVT_LOOP();
  NW_LOG(NW_LOG_LEVEL_ERRO, "Exit from eventloop, no events to process!");

  /*---------------------------------------------------------------------------
   *  Destroy Gtpv2c Stack Instance
   *--------------------------------------------------------------------------*/
  rc = nwGtpv2cFinalize(hGtpv2cStack);
  if(rc != NW_OK)
  {
    NW_LOG(NW_LOG_LEVEL_ERRO, "Failed to finalize gtpv2c stack instance. Error '%u' occured", rc);
  }

  return rc;
}

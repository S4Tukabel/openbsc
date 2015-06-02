#define __WITH_LIBEVENT__

#include <stdio.h>
#include <assert.h>
#include <signal.h>

#include <mylib/NwLog.h>
#include <mylib/NwGtpv2c.h>

#include "NwEvt.h"
#include "openbsc/NwMiniLogMgrEntity.h"
#include "openbsc/NwMiniTmrMgrEntity.h"
#include "openbsc/NwMiniUdpEntity.h"
#include "openbsc/NwMiniUlpEntity.h"

#include <mylib/NwTypes.h>
#include <mylib/NwError.h>
//#include <mylib/NwLogMgr.h>
//#include <mylib/NwSaeGwUeLog.h>
//#include <mylib/NwSaeGwUeState.h>
#include <mylib/NwGtpv2cIe.h>
#include <mylib/NwGtpv2cMsg.h>

//#include <mylib/NwSaeGwUlp.h>

#include <openbsc/sgsn_s4.h>
#include <openbsc/debug.h>

// superkabel includes
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "NwEvt.h"
#include "NwLog.h"
#include "NwMem.h"
#include "NwUtils.h"
#include "NwSaeGwLog.h"
#include "NwLogMgr.h"
#include "NwGtpv2c.h"
#include "NwSaeGwUe.h"
#include "NwSaeGwUlp.h"
#include "NwGtpv2cIf.h"
#include "NwSaeGwDpe.h"



//FROM nwMain
typedef struct
{
  NwU8T                         isCombinedGw;
  NwU8T                         apn[1024];
  NwU32T                        ippoolSubnet;
  NwU32T                        ippoolMask;
  NwU32T                        numOfUe;
  NwGtpv2cIfT                   udp;

  struct {
    NwU32T                      s11cIpv4Addr;
    NwU32T                      s5cIpv4Addr;
    NwU32T                      s4cIpv4Addr;
    NwU32T                      s1uIpv4Addr;
    NwSaeGwUlpT                 *pGw;
  } sgwUlp;

  struct {
    NwU32T                      s5cIpv4Addr;
    NwU32T                      s5uIpv4Addr;
    NwSaeGwUlpT                 *pGw;
  } pgwUlp;
  
  struct {
    NwU32T                      s4cIpv4Addr;
    NwU32T                      s4uIpv4Addr;
    NwSaeGwUlpT                 *pGw;
  } sgsnUlp;
  
  struct {
    NwSaeGwDpeT                 *pDpe;           /*< Data Plane Entity   */
    NwU32T                      gtpuIpv4Addr;
    NwU8T                       sgiNwIfName[128];
  } dataPlane;
} NwSaeGwT;



typedef struct NwGtpv2cPeerS
{
  NwU32T ipv4Addr;
  NwU32T pingCount;
  NwU32T pingInterval;
  NwU32T t3Time;
  NwU32T n3Count;

  NwU32T sendTimeStamp;
  NwGtpv2cTunnelHandleT hTunnel;
} NwGtpv2cPeerT;


NwSaeGwT saeGw;

// old vars
static NwGtpv2cNodeUlpT              ulpObj;
static NwGtpv2cNodeUdpT              udpObj;
static NwGtpv2cStackHandleT          hGtpv2cStack = 0;
  
NwRcT tukabel_tunel_test(NwGtpv2cNodeUlpT* thiz,NwU32T peerIp);
NwRcT nwSaeGwInitialize(NwSaeGwT* thiz);
NwRcT nwSaeGwFinalize(NwSaeGwT*  thiz);

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
                    val = val | (((str[n + 1]-'0') & 0xf) << 4);
                else
                    val = val | (0xf << 4);
                
                imsi[n / 2] = val;
	}
}

/* TS 29.274 v10.9.0 section 7.2.1: Create Session Request */
NwRcT sgsn_s4_send_create_session_request(/*NwSaeGwUeT* thiz, NwGtpv2cUlpTrxnHandleT hTrxn, */ struct sgsn_mm_ctx *mmctx) 
{
  NwRcT rc;
  NwGtpv2cUlpApiT       ulpReq;
  NwU8T imsi[8];
  NwU8T msisdn[8];
  NwU8T mei[8];
  NwU8T service_network[3];
  NwSaeGwPaaT paa;
  NwU8T apn[] = "internet";  
  NwU32T ip_addr_sgsn = inet_addr("127.0.0.40");
  NwU32T ip_addr_sgw = inet_addr("127.0.0.41");
  NwGtpv2cStackHandleT gtpv2_stack = saeGw.sgsnUlp.pGw->sgsn.s4c.hGtpv2cStack;

  rc = nwGtpv2cMsgNew( gtpv2_stack,
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
  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_MSISDN, 8, 0, msisdn);
  NW_ASSERT( NW_OK == rc );

  imsi_str2arr(mmctx->imei, mei);
  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_MEI, 8, 0, mei);
  NW_ASSERT( NW_OK == rc );

  /* 2 = GERAN*/
  rc = nwGtpv2cMsgAddIeTV1((ulpReq.hMsg), NW_GTPV2C_IE_RAT_TYPE, 0, 2);
  NW_ASSERT( NW_OK == rc );

  /* Serving Network = MCC + MNC (part of imsi)*/
  memcpy(service_network, imsi, 3);
  service_network[2] = (service_network[2] << 4) | (service_network[1] >> 4);
  service_network[1] |= 0xf0;
  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_SERVING_NETWORK, 3, 0, service_network);
  NW_ASSERT( NW_OK == rc );

  /* Sender F-TEID for Control Plane */
  /* NW_GTPV2C_IFTYPE_S4_SGSN_GTPC (17)*/
  // TODO: IPv4
  rc = nwGtpv2cMsgAddIeFteid((ulpReq.hMsg), NW_GTPV2C_IE_INSTANCE_ZERO, NW_GTPV2C_IFTYPE_S4_SGSN_GTPC, (NwU32T)mmctx, htonl(ip_addr_sgsn), NULL);
  NW_ASSERT( NW_OK == rc );

  rc = nwGtpv2cMsgAddIeTV1((ulpReq.hMsg), NW_GTPV2C_IE_SELECTION_MODE, 0, 0x02);
  NW_ASSERT( NW_OK == rc );

  rc = nwGtpv2cMsgAddIeTV1((ulpReq.hMsg), NW_GTPV2C_IE_PDN_TYPE, 0, NW_PDN_TYPE_IPv4);
  NW_ASSERT( NW_OK == rc );

  /* TS 29.274 v10.9.0 section 7.2.1: */
  /* If static IP address assignment the IPv4 address shall be set to 0.0.0.0 */
  paa.pdnType = NW_PDN_TYPE_IPv4;
  paa.ipv4Addr[0] = 0x00;
  paa.ipv4Addr[1] = 0x00;
  paa.ipv4Addr[2] = 0x00;
  paa.ipv4Addr[3] = 0x00;
  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_PAA, sizeof(paa), 0, (NwU8T*)&paa);
  NW_ASSERT( NW_OK == rc );

  // TODO: APN detect
  rc = nwGtpv2cMsgAddIe((ulpReq.hMsg), NW_GTPV2C_IE_APN, strlen(apn), NW_GTPV2C_IE_INSTANCE_ZERO, apn);
  NW_ASSERT( NW_OK == rc );

  /* No APN restriction */
  rc = nwGtpv2cMsgAddIeTV1((ulpReq.hMsg), NW_GTPV2C_IE_APN_RESTRICTION, 0, 0);
  NW_ASSERT( NW_OK == rc );

  /* Bearer Contexts to be created - start of grouped IE  */
  rc = nwGtpv2cMsgGroupedIeStart((ulpReq.hMsg), NW_GTPV2C_IE_BEARER_CONTEXT, 0);
  NW_ASSERT( NW_OK == rc );

    /* EBI = 5 - first non reserved bearer for default bearer */
    rc = nwGtpv2cMsgAddIeTV1((ulpReq.hMsg), NW_GTPV2C_IE_EBI, NW_GTPV2C_IE_INSTANCE_ZERO, 5);
    NW_ASSERT( NW_OK == rc );

    /* S4-U SGSN F-TEID */
    /* NW_GTPV2C_IFTYPE_S4_SGSN_GTPU (15) */
    // TODO: TEID (bulgarian constant now)
    rc = nwGtpv2cMsgAddIeFteid((ulpReq.hMsg),
        NW_GTPV2C_IE_INSTANCE_TWO,
        NW_GTPV2C_IFTYPE_S4_SGSN_GTPU,
        ((NwU32T)(3)),
        htonl(ip_addr_sgsn),
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

  /* Send Create Session Request to SGW */
  ulpReq.apiType = (NW_GTPV2C_ULP_API_INITIAL_REQ | NW_GTPV2C_ULP_API_FLAG_CREATE_LOCAL_TUNNEL);
  ulpReq.apiInfo.initialReqInfo.hTunnel         = 0;                       
  ulpReq.apiInfo.initialReqInfo.hUlpTrxn        = 0; //tukabel zero/// hTrxn;                        /* Save the trxn for Response */
  ulpReq.apiInfo.initialReqInfo.hUlpTunnel      = (NwGtpv2cUlpTrxnHandleT)mmctx;
  ulpReq.apiInfo.initialReqInfo.teidLocal       = (NwGtpv2cUlpTrxnHandleT)mmctx;
  ulpReq.apiInfo.initialReqInfo.peerIp          = htonl(ip_addr_sgw);

  rc = nwGtpv2cProcessUlpReq(gtpv2_stack, &ulpReq);
  NW_ASSERT( NW_OK == rc );

  //thiz->s5s8cTunnel.hSgwLocalTunnel = ulpReq.apiInfo.initialReqInfo.hTunnel;

  //first param: LOGL_INFO	3 //not found?!!
  LOGMMCTXP(LOGL_INFO, mmctx, "-> CREATE SESSION REQ: IMSI=%s <TUKABEL>\n", mmctx->imsi);

  return rc;
}


void S4Initialize(NwU8T localIpStr[20], NwU8T targetIpStr[20])
{
  NwRcT                         rc; 
  NwU32T                        logLevel;
  NwU8T*                        logLevelStr;

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
  //tukabel_tunel_test(&ulpObj,inet_addr(targetIpStr));
  
//  NW_LOG(NW_LOG_LEVEL_NOTI, "EGTPING %s ("NW_IPV4_ADDR")", targetIpStr, NW_IPV4_ADDR_FORMAT(inet_addr(targetIpStr)));
//  rc = nwGtpv2cUlpPing(&ulpObj, 
//                        inet_addr(targetIpStr),
//                        4,
//                        10,
//                        2,
//                        3);
//  NW_ASSERT(NW_OK == rc);

  /*---------------------------------------------------------------------------
   * Install signal handler 
   *--------------------------------------------------------------------------*/
  //signal(SIGINT, nwEgtPingHandleSignal);

  /*---------------------------------------------------------------------------
   * Event loop 
   *--------------------------------------------------------------------------*/

  //NW_EVT_LOOP();
  //NW_LOG(NW_LOG_LEVEL_ERRO, "Exit from eventloop, no events to process!");

  /*---------------------------------------------------------------------------
   *  Destroy Gtpv2c Stack Instance
   *--------------------------------------------------------------------------*/
}

void S4Finalize() {
  NwRcT rc = nwGtpv2cFinalize(hGtpv2cStack);
  if(rc != NW_OK)
  {
    NW_LOG(NW_LOG_LEVEL_ERRO, "Failed to finalize gtpv2c stack instance. Error '%u' occured", rc);
  }
}

//NwRcT tukabel_tunel_test(NwGtpv2cNodeUlpT* thiz,NwU32T peerIp)
//{
//  NwRcT rc;
//  NwGtpv2cUlpApiT       ulpReq;
//  NwGtpv2cPeerT         *pPeer;
//  NW_LOG(NW_LOG_LEVEL_ERRO, "pivo");
//  pPeer = nwGtpv2cUlpCreatePeerContext(thiz, peerIp);
////  NwU8T imsi[8];
////  NwU8T msisdn[8];
////  NwU8T mei[8];
////  NwU8T service_network[3];
////  NwSaeGwPaaT paa;
////  NwU8T apn[] = "internet";  
////  NwU32T ip_addr = inet_ntoa("127.0.0.4");
// NW_LOG(NW_LOG_LEVEL_ERRO, "rum");
//  rc = nwGtpv2cMsgNew( thiz->hGtpv2cStack,
//      NW_FALSE,                                          /* TIED present*/
//      NW_GTP_CREATE_SESSION_REQ,                        /* Msg Type    */
//      0,                                                /* TEID        */
//      0,                                                /* Seq Number  */
//      &(ulpReq.hMsg));
//  NW_LOG(NW_LOG_LEVEL_ERRO, "vodka");
//  NW_ASSERT( NW_OK == rc );
//  NW_LOG(NW_LOG_LEVEL_ERRO, "az tu");
//   
//  ulpReq.apiType = NW_GTPV2C_ULP_API_INITIAL_REQ;
//  ulpReq.apiInfo.initialReqInfo.hTunnel         = pPeer->hTunnel;
//  ulpReq.apiInfo.initialReqInfo.hUlpTrxn        = (NwGtpv2cUlpTrxnHandleT)pPeer;
//  ulpReq.apiInfo.initialReqInfo.hUlpTunnel      = (NwGtpv2cUlpTunnelHandleT)pPeer;
//
//  rc = nwGtpv2cProcessUlpReq(thiz->hGtpv2cStack, &ulpReq);
//  NW_ASSERT( NW_OK == rc );
//
//  //thiz->s5s8cTunnel.hSgwLocalTunnel = ulpReq.apiInfo.initialReqInfo.hTunnel;
//
//  //LOGMMCTXP(LOGL_INFO, mmctx, "-> CREATE SESSION REQ: IMSI=%s <TUKABEL>\n", mmctx->imsi);
//
//  return rc;
//}

void sgsn_s4_initialize() {
  NwRcT rc; 
  
  // Erase saeGw
  memset(&saeGw, 0, sizeof(NwSaeGwT));
  
  // TODO: load from config or args
  saeGw.numOfUe         = 100;
  saeGw.sgsnUlp.s4cIpv4Addr = ntohl(inet_addr("127.0.4.4"));
  
  /*---------------------------------------------------------------------------
   *  Initialize event library
   *--------------------------------------------------------------------------*/

  NW_EVT_INIT();

  /*---------------------------------------------------------------------------
   *  Initialize Memory Manager 
   *--------------------------------------------------------------------------*/

  rc = nwMemInitialize();
  NW_ASSERT(NW_OK == rc);

  /*---------------------------------------------------------------------------
   *  Initialize LogMgr
   *--------------------------------------------------------------------------*/

  rc = nwLogMgrInit(nwLogMgrGetInstance(), (NwU8T*)"NW-SAEGW", getpid());
  NW_ASSERT(NW_OK == rc);

  /*---------------------------------------------------------------------------
   * Initialize SAE GW 
   *--------------------------------------------------------------------------*/

  rc =  nwSaeGwInitialize(&saeGw);
  NW_ASSERT(NW_OK == rc);

  /*---------------------------------------------------------------------------
   * Event Loop 
   *--------------------------------------------------------------------------*/

  NW_EVT_LOOP();

  NW_SAE_GW_LOG(NW_LOG_LEVEL_ERRO, "Exit from eventloop, no events to process!");

  /*---------------------------------------------------------------------------
   * Finalize SAE GW 
   *--------------------------------------------------------------------------*/

  rc =  nwSaeGwFinalize(&saeGw);
  NW_ASSERT(NW_OK == rc);

  rc =  nwMemFinalize();
  NW_ASSERT(NW_OK == rc);
 
}


NwRcT nwSaeGwInitialize(NwSaeGwT* thiz)
{
  NwRcT rc = NW_OK;
  NwSaeGwUlpT* pGw;
  NwSaeGwUlpConfigT cfg;

  /* Create Data Plane instance. */

  thiz->dataPlane.pDpe = nwSaeGwDpeInitialize();

  /* Create SGW and PGW ULP instances. */
  if(thiz->sgwUlp.s11cIpv4Addr)
  {

    NW_SAE_GW_LOG(NW_LOG_LEVEL_NOTI, "Creating SGW instance with S11 IPv4 address "NW_IPV4_ADDR, NW_IPV4_ADDR_FORMAT(htonl(thiz->sgwUlp.s11cIpv4Addr)));

    cfg.maxUeSessions   = thiz->numOfUe;
    cfg.ippoolSubnet    = thiz->ippoolSubnet;
    cfg.ippoolMask      = thiz->ippoolMask;
    cfg.s11cIpv4Addr    = thiz->sgwUlp.s11cIpv4Addr;
    cfg.s5cIpv4AddrSgw  = thiz->sgwUlp.s5cIpv4Addr;
    cfg.s4cIpv4AddrSgw  = thiz->sgwUlp.s4cIpv4Addr;
    cfg.pDpe            = thiz->dataPlane.pDpe;

    strncpy((char*)cfg.apn, (const char*)thiz->apn, 1023);

    pGw = nwSaeGwUlpNew(); 
    rc = nwSaeGwUlpInitialize(pGw, NW_SAE_GW_TYPE_SGW, &cfg);
    NW_ASSERT( NW_OK == rc );
    thiz->sgwUlp.pGw = pGw;
  }

  if(thiz->pgwUlp.s5cIpv4Addr)
  {

    NW_SAE_GW_LOG(NW_LOG_LEVEL_NOTI, "Creating PGW instance with S5 Ipv4 address "NW_IPV4_ADDR, NW_IPV4_ADDR_FORMAT(htonl(thiz->pgwUlp.s5cIpv4Addr)));

    cfg.maxUeSessions   = thiz->numOfUe;
    cfg.ippoolSubnet    = thiz->ippoolSubnet;
    cfg.ippoolMask      = thiz->ippoolMask;
    cfg.s5cIpv4AddrPgw  = thiz->pgwUlp.s5cIpv4Addr;
    cfg.pDpe            = thiz->dataPlane.pDpe;

    strncpy((char*)cfg.apn, (const char*)thiz->apn, 1023);

    pGw = nwSaeGwUlpNew(); 
    rc = nwSaeGwUlpInitialize(pGw, NW_SAE_GW_TYPE_PGW, &cfg);
    NW_ASSERT( NW_OK == rc );
    thiz->pgwUlp.pGw = pGw;
  }
  
  /* Create SGSN ULP instance */
  if(thiz->sgsnUlp.s4cIpv4Addr)
  {

    NW_SAE_GW_LOG(NW_LOG_LEVEL_NOTI, "Creating SGSN instance with S4 IPv4 address "NW_IPV4_ADDR, NW_IPV4_ADDR_FORMAT(htonl(thiz->sgsnUlp.s4cIpv4Addr)));

    cfg.maxUeSessions   = thiz->numOfUe;
    cfg.ippoolSubnet    = thiz->ippoolSubnet;
    cfg.ippoolMask      = thiz->ippoolMask;
    cfg.s4cIpv4AddrSgsn = thiz->sgsnUlp.s4cIpv4Addr;
    cfg.pDpe            = thiz->dataPlane.pDpe;

    strncpy((char*)cfg.apn, (const char*)thiz->apn, 1023);

    pGw = nwSaeGwUlpNew(); 
    rc = nwSaeGwUlpInitialize(pGw, NW_SAE_GW_TYPE_SGW, &cfg);
    NW_ASSERT( NW_OK == rc );
    thiz->sgsnUlp.pGw = pGw;
  }

  /* Register collocated PGW, if any */
  if(thiz->isCombinedGw && 
      (thiz->sgwUlp.pGw && thiz->pgwUlp.pGw))
  {
    rc = nwSaeGwUlpRegisterCollocatedPgw(thiz->sgwUlp.pGw, thiz->pgwUlp.pGw);
    NW_ASSERT(NW_OK == rc);
  }

  if(thiz->dataPlane.gtpuIpv4Addr)
  {
    rc = nwSaeGwDpeCreateGtpuService(thiz->dataPlane.pDpe, thiz->dataPlane.gtpuIpv4Addr);
  }

  if(strlen((const char*)(thiz->dataPlane.sgiNwIfName)) != 0)
  {
    rc = nwSaeGwDpeCreateIpv4Service(thiz->dataPlane.pDpe, thiz->dataPlane.sgiNwIfName);
  }
 
  return rc;
}

NwRcT
nwSaeGwFinalize(NwSaeGwT*  thiz)
{
  return NW_OK;
}
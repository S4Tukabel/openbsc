/*----------------------------------------------------------------------------*
 *                                                                            *
 *            M I N I M A L I S T I C     U L P     E N T I T Y               *
 *                                                                            *
 *                    Copyright (C) 2010 Amit Chawre.                         *
 *                                                                            *
 *----------------------------------------------------------------------------*/

/** 
 * @file NwMiniUlpEntity.c
 * @brief This file contains example of a minimalistic ULP entity.
*/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include "openbsc/NwEvt.h"
#include <mylib/NwGtpv2c.h>
#include <mylib/NwGtpv2cIe.h>
#include <mylib/NwGtpv2cMsg.h>
#include <mylib/NwGtpv2cMsgParser.h>
#include "openbsc/NwMiniLogMgrEntity.h"
#include "openbsc/NwMiniUlpEntity.h"
#include "openbsc/sgsn_s4.h"

// logging
#include <openbsc/debug.h>

#ifndef NW_ASSERT
#define NW_ASSERT assert
#endif 

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct
{
  NwGtpv2cErrorT                error;
  //NwSaeGwEpsBearerT             epsBearerCreated;
  //NwSaeGwEpsBearerT             epsBearerRemoved;
} NwSaeGwUePgwCreateSessionResponseT;
    
static
NwCharT* gLogLevelStr[] = {"EMER", "ALER", "CRIT",  "ERRO", "WARN", "NOTI", "INFO", "DEBG"};

/*---------------------------------------------------------------------------
 * Public Functions
 *--------------------------------------------------------------------------*/

NwRcT
nwGtpv2cUlpInit(NwGtpv2cNodeUlpT* thiz, NwGtpv2cStackHandleT hGtpv2cStack, char* peerIpStr)
{
  NwRcT rc;
  thiz->hGtpv2cStack = hGtpv2cStack;
  strcpy(thiz->peerIpStr, peerIpStr);
  return NW_OK;
}

NwRcT
nwGtpv2cUlpDestroy(NwGtpv2cNodeUlpT* thiz)
{
  NW_ASSERT(thiz);
  memset(thiz, 0, sizeof(NwGtpv2cNodeUlpT));
  return NW_OK;
}

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

NwGtpv2cPeerT*
nwGtpv2cUlpCreatePeerContext(NwGtpv2cNodeUlpT* thiz, NwU32T peerIp)
{
  NwRcT                 rc;
  NwGtpv2cUlpApiT       ulpReq;
  NwGtpv2cPeerT         *pPeer = (NwGtpv2cPeerT*) malloc(sizeof(NwGtpv2cPeerT));

  if(pPeer)
  {
    pPeer->ipv4Addr = peerIp;

    /*
     *  Send Message Request to Gtpv2c Stack Instance
     */

    ulpReq.apiType = NW_GTPV2C_ULP_CREATE_LOCAL_TUNNEL;

    ulpReq.apiInfo.createLocalTunnelInfo.hTunnel         = 0;
    ulpReq.apiInfo.createLocalTunnelInfo.hUlpTunnel      = (NwGtpv2cUlpTrxnHandleT)thiz;
    ulpReq.apiInfo.createLocalTunnelInfo.teidLocal       = (NwGtpv2cUlpTrxnHandleT)0;
    ulpReq.apiInfo.createLocalTunnelInfo.peerIp          = htonl(peerIp);

    rc = nwGtpv2cProcessUlpReq(thiz->hGtpv2cStack, &ulpReq);
    NW_ASSERT(NW_OK == rc);
    pPeer->hTunnel = ulpReq.apiInfo.createLocalTunnelInfo.hTunnel;
  }
  return pPeer;

}

NwRcT
nwGtpv2cUlpSendEchoRequestToPeer(NwGtpv2cNodeUlpT* thiz, NwGtpv2cPeerT *pPeer)
{
  NwRcT                 rc;
  struct timeval        tv;
  NwGtpv2cUlpApiT       ulpReq;
  /*
   *  Send Message Request to Gtpv2c Stack Instance
   */

  ulpReq.apiType = NW_GTPV2C_ULP_API_INITIAL_REQ;

  ulpReq.apiInfo.initialReqInfo.hTunnel         = pPeer->hTunnel;
  ulpReq.apiInfo.initialReqInfo.hUlpTrxn        = (NwGtpv2cUlpTrxnHandleT)pPeer;
  ulpReq.apiInfo.initialReqInfo.hUlpTunnel      = (NwGtpv2cUlpTunnelHandleT)pPeer;

  rc = nwGtpv2cMsgNew( thiz->hGtpv2cStack,
      NW_FALSE,
      NW_GTP_ECHO_REQ,
      0,
      0,
      &(ulpReq.hMsg));

  NW_ASSERT(NW_OK == rc);

  rc = nwGtpv2cMsgAddIeTV1((ulpReq.hMsg), NW_GTPV2C_IE_RECOVERY, 0, thiz->restartCounter);
  NW_ASSERT(NW_OK == rc);

  NW_ASSERT(gettimeofday(&tv, NULL) == 0);
  pPeer->sendTimeStamp = (tv.tv_sec * 1000000) + tv.tv_usec;

  rc = nwGtpv2cProcessUlpReq(thiz->hGtpv2cStack, &ulpReq);
  NW_ASSERT(NW_OK == rc);

  return NW_OK;
}

NwRcT
nwGtpv2cUlpPing(NwGtpv2cNodeUlpT* thiz,
                NwU32T peerIp,
                NwU32T pingCount,
                NwU32T pingInterval,
                NwU32T t3Time,
                NwU32T n3Count)
{
  NwRcT                 rc;
  NwGtpv2cPeerT         *pPeer;
  NwGtpv2cUlpApiT       ulpReq;

  pPeer = nwGtpv2cUlpCreatePeerContext(thiz, peerIp);

  pPeer->pingCount      = pingCount;
  pPeer->pingInterval   = pingInterval;
  pPeer->t3Time         = t3Time;
  pPeer->n3Count        = n3Count;
  /*
   *  Send Echo Request to peer
   */

  rc = nwGtpv2cUlpSendEchoRequestToPeer(thiz, pPeer);

  return rc;
}

NwRcT 
nwGtpv2cUlpProcessStackReqCallback (NwGtpv2cUlpHandleT hUlp, 
                       NwGtpv2cUlpApiT *pUlpApi)
{
  NwRcT                 rc;
  NwU32T                seqNum;
  NwU32T                len;
  NwU32T                recvTimeStamp;
  struct timeval        tv;
  NwGtpv2cPeerT         *pPeer;
  NwGtpv2cNodeUlpT*     thiz;
  NwU8T *pPaaBuf;
  NwU16T paaBufLen;
  NwSaeGwPaaT paa;
  NW_ASSERT(pUlpApi != NULL);

  thiz = (NwGtpv2cNodeUlpT*) hUlp;

  LOGPC(DMM, LOGL_INFO, "TUKABEL LOGPC: Prijal som <> apitype= %d\n", pUlpApi->apiType);
  switch(pUlpApi->apiType)
  {
    case NW_GTPV2C_ULP_API_TRIGGERED_RSP_IND:
      {
        pPeer = (NwGtpv2cPeerT*)pUlpApi->apiInfo.triggeredRspIndInfo.hUlpTrxn;
        NW_LOG(NW_LOG_LEVEL_NOTI, "TUKABEL: Prijal som spravu" );
        LOGPC(DMM, LOGL_INFO, "TUKABEL LOGPC: Prijal som spravu\n");
        
        if(pUlpApi->apiInfo.triggeredRspIndInfo.msgType == NW_GTP_ECHO_RSP)
        {
          seqNum = nwGtpv2cMsgGetSeqNumber(pUlpApi->hMsg);
          len = nwGtpv2cMsgGetLength(pUlpApi->hMsg);

          NW_ASSERT(gettimeofday(&tv, NULL) == 0);
          recvTimeStamp = (tv.tv_sec * 1000000) + tv.tv_usec;

          NW_LOG(NW_LOG_LEVEL_NOTI, "%u bytes of response from "NW_IPV4_ADDR": gtp_seq=%u time=%2.2f ms", len, NW_IPV4_ADDR_FORMAT(pPeer->ipv4Addr), seqNum, (float) (recvTimeStamp - pPeer->sendTimeStamp) / 1000 );
          if(pPeer->pingCount)
          {
            sleep(pPeer->pingInterval);
            rc = nwGtpv2cUlpSendEchoRequestToPeer(thiz, pPeer);
            if(pPeer->pingCount != 0xffffffff) pPeer->pingCount--;
          }
        }
        if(pUlpApi->apiInfo.triggeredRspIndInfo.msgType == NW_GTP_CREATE_SESSION_RSP)
        {
            NwGtpv2cMsgHandleT hReqMsg = pUlpApi->hMsg;
            //NwSaeGwUePgwCreateSessionResponseT pCreateSessReq;
            seqNum = nwGtpv2cMsgGetSeqNumber(pUlpApi->hMsg);
            len = nwGtpv2cMsgGetLength(pUlpApi->hMsg);
            NW_LOG(NW_LOG_LEVEL_NOTI, "TUKABEL: Prijal som response" );
            rc = nwGtpv2cMsgGetIeFteid(hReqMsg,
            NW_GTPV2C_IE_INSTANCE_ONE,
            &thiz->s4Tunnel.fteid.ifType,
            &thiz->s4Tunnel.fteid.teidOrGreKey,
            &thiz->s4Tunnel.fteid.ipv4Addr,
            &thiz->s4Tunnel.fteid.ipv6Addr[0]);
            if( NW_OK != rc )
            {
              return rc;
            }
               
            if((rc = nwGtpv2cMsgGetIeTlvP(hReqMsg, NW_GTPV2C_IE_PAA, NW_GTPV2C_IE_INSTANCE_ZERO, &pPaaBuf, &paaBufLen)) != NW_OK)
            {
                return rc;
            }
            paa.pdnType = *pPaaBuf;

            if(paa.pdnType == NW_PDN_TYPE_IPv4)
            {
              pPaaBuf++;
              memcpy(paa.ipv4Addr, pPaaBuf, 4);
              return NW_OK;
            }
            NW_LOG(NW_LOG_LEVEL_NOTI, "TUKABEL: Prijal som response" );
            LOGPC(DMM, LOGL_INFO, "TUKABEL LOGPC: Prijal som response teid = %u\n", thiz->s4Tunnel.fteid.teidOrGreKey);
        }
      }
      break;

    case NW_GTPV2C_ULP_API_RSP_FAILURE_IND:
      {
        pPeer = (NwGtpv2cPeerT*)pUlpApi->apiInfo.rspFailureInfo.hUlpTrxn;
        NW_LOG(NW_LOG_LEVEL_DEBG, "No response from "NW_IPV4_ADDR" (2123)!", NW_IPV4_ADDR_FORMAT(pPeer->ipv4Addr));
        rc = nwGtpv2cUlpSendEchoRequestToPeer(thiz, pPeer);
      }
      break;

    default:
      NW_LOG(NW_LOG_LEVEL_WARN, "Received undefined UlpApi from gtpv2c stack!");
  }
  return NW_OK;
}

#ifdef __cplusplus
}
#endif

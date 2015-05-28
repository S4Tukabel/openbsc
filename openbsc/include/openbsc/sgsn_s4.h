/* 
 * File:   sgsn_s4.h
 * Author: tomx
 *
 * Created on May 27, 2015, 8:05 PM
 */

    

#ifndef SGSN_S4_H
#define	SGSN_S4_H

#include <stdio.h>
#include <assert.h>

#include <openbsc/gprs_sgsn.h>

#include <mylib/tree.h>
#include <mylib/NwLog.h>
#include <mylib/NwTypes.h>
#include <mylib/NwGtpv2c.h>
#include <mylib/NwGtpv2cMsgParser.h>
    

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum
{
  NW_SAE_GW_UE_STATE_INIT = 0,
  NW_SAE_GW_UE_STATE_SAE_SESSION_CREATED,
  NW_SAE_GW_UE_STATE_SGW_SESSION_CREATED,
  NW_SAE_GW_UE_STATE_PGW_SESSION_CREATED,
  NW_SAE_GW_UE_STATE_PGW_SESSION_ESTABLISHED = NW_SAE_GW_UE_STATE_PGW_SESSION_CREATED,
  NW_SAE_GW_UE_STATE_SAE_SESSION_ESTABLISHED,
  NW_SAE_GW_UE_STATE_SGW_SESSION_ESTABLISHED,
  NW_SAE_GW_UE_STATE_WT_PGW_CREATE_SESSION_RSP,
  NW_SAE_GW_UE_STATE_WT_PGW_DELETE_SESSION_RSP,
  NW_SAE_GW_UE_STATE_WT_PGW_MODIFY_BEARER_RSP,  /* Modify Bearer Sent during X2 based HO with SGW relocation */
  NW_SAE_GW_UE_STATE_WT_PGW_MODIFY_BEARER_RSP2, /* Modify Bearer Sent during S1 based HO with SGW relocation */
  NW_SAE_GW_UE_STATE_END
} NwUeStateT;

/**
 * Fully Qualified Tunnel Endpoint Identifier aka FTEID
 */
typedef struct 
{
  NwBoolT isValid;
  NwBoolT isIpv4;
  NwBoolT isIpv6;
  NwU8T   ifType;
  NwU32T  teidOrGreKey;
  NwU32T  ipv4Addr;
  NwU8T   ipv6Addr[16];
} NwSaeGwFteidT;

typedef struct
{
  NwU8T pdnType;
  NwU8T ipv4Addr[4];
} NwSaeGwPaaT;

typedef NwPtrT NwDpeBearerHandleT;
    
typedef struct NwSaeGwUe
{
  NwU8T                         imsi[8];
  NwU8T                         msIsdn[8];
  NwU8T                         mei[8];

  NwU8T                         servingNetwork[3];
  NwU8T                         ratType;
  NwU8T                         selMode;
  NwU8T                         pdnType;

  struct {
    NwU8T       v[256];
    NwU16T      l;
  }                             apn;

  NwU8T                         apnRes;

  NwSaeGwPaaT                   paa;

  NwU32T                        sessionType;
  NwU32T                        hSgw;
  NwU32T                        hPgw;
  NwUeStateT                    state;

  NwGtpv2cStackHandleT          hGtpv2cStackSgwS11;
  NwGtpv2cStackHandleT          hGtpv2cStackSgwS5;
  NwGtpv2cStackHandleT          hGtpv2cStackPgwS5;

  struct {
    NwSaeGwFteidT               fteidMme;
    NwSaeGwFteidT               fteidSgw;
    NwGtpv2cTunnelHandleT       hSgwLocalTunnel;
  }                             s11cTunnel;

  struct {
    NwSaeGwFteidT               fteidPgw;
    NwSaeGwFteidT               fteidSgw;
    NwGtpv2cTunnelHandleT       hSgwLocalTunnel;
    NwGtpv2cTunnelHandleT       hPgwLocalTunnel;
  }                             s5s8cTunnel;

#define NW_SAE_GW_MAX_EPS_BEARERS               (16)
  struct {
    NwBoolT                     isValid;
    NwDpeBearerHandleT          hSgwUplink;
    NwDpeBearerHandleT          hSgwDownlink;
    NwDpeBearerHandleT          hPgwUplink;
    NwDpeBearerHandleT          hPgwDownlink;

    struct {
      NwSaeGwFteidT             fteidEnodeB;
      NwSaeGwFteidT             fteidSgw;
    } s1uTunnel;

    struct {
      NwSaeGwFteidT             fteidPgw;
      NwSaeGwFteidT             fteidSgw;
    } s5s8uTunnel;

  }                             epsBearer[NW_SAE_GW_MAX_EPS_BEARERS];


  RB_ENTRY (NwSaeGwUe)          ueSgwSessionRbtNode;                      /**< RB Tree Data Structure Node        */
  RB_ENTRY (NwSaeGwUe)          uePgwSessionRbtNode;                      /**< RB Tree Data Structure Node        */
} NwSaeGwUeT;

NwRcT sgsn_s4_send_create_session_request(NwSaeGwUeT* thiz, struct sgsn_mm_ctx *mmctx);
#ifdef	__cplusplus
}
#endif

#endif	/* SGSN_S4_H */


/*----------------------------------------------------------------------------*
 *                                                                            *
 *         M I N I M A L I S T I C    T M R M G R     E N T I T Y             *
 *                                                                            *
 *                    Copyright (C) 2010 Amit Chawre.                         *
 *                                                                            *
 *----------------------------------------------------------------------------*/


/** 
 * @file NwMiniTmrMgrEntity.c
 * @brief This file ontains example of a minimalistic timer manager entity.
*/

#include <stdio.h>
#include <assert.h>
#include "NwEvt.h"
#include <mylib/NwLog.h>

#ifndef NW_ASSERT
#define NW_ASSERT assert
#endif 

#ifndef __NW_MINI_TMR_MGR_H__
#define __NW_MINI_TMR_MGR_H__

typedef struct
{
  NwU8T _tbd;
} NwGtpv2cNodeTmrMgrT;

typedef struct
{
  NwEventT      ev;
  void*         timeoutArg;
} NwGtpv2cNodeTmrT;


#ifdef __cplusplus
extern "C" {
#endif

NwRcT nwTimerStart( NwGtpv2cTimerMgrHandleT tmrMgrHandle,
    NwU32T timeoutSec,
    NwU32T timeoutUsec,
    NwU32T tmrType,
    void*  timeoutArg,
    NwGtpv2cTimerHandleT* hTmr);


NwRcT nwTimerStop( NwGtpv2cTimerMgrHandleT tmrMgrHandle,
    NwGtpv2cTimerHandleT hTmr);


#ifdef __cplusplus
}
#endif

#endif

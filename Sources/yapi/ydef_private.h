/*********************************************************************
 *
 * $Id: ydef.h 39141 2020-01-15 16:02:31Z seb $
 *
 * Standard definitions common to all yoctopuce projects
 *
 * - - - - - - - - - License information: - - - - - - - - -
 *
 *  Copyright (C) 2011 and beyond by Yoctopuce Sarl, Switzerland.
 *
 *  Yoctopuce Sarl (hereafter Licensor) grants to you a perpetual
 *  non-exclusive license to use, modify, copy and integrate this
 *  file into your software for the sole purpose of interfacing
 *  with Yoctopuce products.
 *
 *  You may reproduce and distribute copies of this file in
 *  source or object form, as long as the sole purpose of this
 *  code is to interface with Yoctopuce products. You must retain
 *  this notice in the distributed source file.
 *
 *  You should refer to Yoctopuce General Terms and Conditions
 *  for additional information regarding your rights and
 *  obligations.
 *
 *  THE SOFTWARE AND DOCUMENTATION ARE PROVIDED "AS IS" WITHOUT
 *  WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 *  WITHOUT LIMITATION, ANY WARRANTY OF MERCHANTABILITY, FITNESS
 *  FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO
 *  EVENT SHALL LICENSOR BE LIABLE FOR ANY INCIDENTAL, SPECIAL,
 *  INDIRECT OR CONSEQUENTIAL DAMAGES, LOST PROFITS OR LOST DATA,
 *  COST OF PROCUREMENT OF SUBSTITUTE GOODS, TECHNOLOGY OR
 *  SERVICES, ANY CLAIMS BY THIRD PARTIES (INCLUDING BUT NOT
 *  LIMITED TO ANY DEFENSE THEREOF), ANY CLAIMS FOR INDEMNITY OR
 *  CONTRIBUTION, OR OTHER SIMILAR COSTS, WHETHER ASSERTED ON THE
 *  BASIS OF CONTRACT, TORT (INCLUDING NEGLIGENCE), BREACH OF
 *  WARRANTY, OR OTHERWISE.
 *
 *********************************************************************/

#ifndef  YOCTO_DEF_PRIVATE_H
#define  YOCTO_DEF_PRIVATE_H
#ifdef  __cplusplus
extern "C" {
#endif

#include "ydef.h"

#if defined(WINDOWS_API)
#if defined(__64BITS__)
typedef u64 BSD_SOCKET;
#else
typedef u32 BSD_SOCKET;
#endif
#define INVALID_BSD_SOCKET  ((BSD_SOCKET)(~0))
#else
typedef int BSD_SOCKET;
#define INVALID_BSD_SOCKET (-1)
#endif

#if 0
#if defined(WINDOWS_API) && (_MSC_VER)
#define YDEBUG_BREAK { __debugbreak();}
#else
#if defined(FREERTOS_API)
#define YDEBUG_BREAK  {__asm__("BKPT");}
#else
#define YDEBUG_BREAK  {__asm__("int3");}
#endif
#endif
#else
#define YDEBUG_BREAK {}
#endif

#if defined(MICROCHIP_API) || defined(FREERTOS_API) || defined(VIRTUAL_HUB)
#define YAPI_IN_YDEVICE
#define YSTATIC
#else
#define YSTATIC static
#endif

#if defined(MICROCHIP_API)
void ypanic(int line);
#define YPANIC panic(__LINE__)
#else
void ypanic(const char *file, int line);
#ifdef FREERTOS_API
#ifndef __FILE_ID__
#define __FILE_ID__ __FILE__
#endif
#define YPANIC {YDEBUG_BREAK;ypanic(__FILE_ID__,__LINE__);}
#else
#define YPANIC YDEBUG_BREAK
#endif
#endif


//#define ENABLE_SSL
#ifndef WINDOWS_API
//#define ENABLE_SSL
#endif

#ifdef  __cplusplus
}
#endif

#endif

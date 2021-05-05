/*********************************************************************
 *
 * $Id: ymemory.h 44847 2021-05-03 09:04:43Z web $
 *
 * Basic memory check function to prevent memory leak
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

#ifndef YMEMORY_H
#define YMEMORY_H
#include "ydef.h"

#ifdef YSAFE_MEMORY
void  ySafeMemoryInit(u32 nbentry);
void* ySafeMalloc(const char *file,u32 line,u32 size);
void  ySafeFree(const char *file,u32 line,void *ptr);
void  ySafeTrace(const char *file,u32 line,void *ptr);
void  ySafeMemoryDump(void *discard);
void  ySafeMemoryStop(void);
#else
#define ySafeMemoryInit(nbentry) {}
#define ySafeMemoryDump(discard) {}
#define ySafeMemoryStop() {}
#endif


/*****************************************************************************
  MEMORY MANAGEMENT FUNCTION:
 ****************************************************************************/

//#define YSAFE_MEMORY

#ifdef YSAFE_MEMORY
#define yMalloc(size)                   ySafeMalloc(__FILE_ID__,__LINE__,size)
#define yFree(ptr)                      {ySafeFree(__FILE_ID__,__LINE__,ptr);ptr=NULL;}
#define yTracePtr(ptr)                  ySafeTrace(__FILE_ID__,__LINE__,ptr)
#ifndef YMEMORY_ALLOW_MALLOC
#undef malloc
#undef free
#define malloc(size)                    yForbiden_malloc(size)
#define free(ptr)                       yForbiden_free(ptr)
#endif
#else
#include <stdlib.h>
#define yMalloc(size)                   malloc(size)
#define yFree(ptr)                      free(ptr)
#define yTracePtr(ptr)
#endif

#define yMemset(dst,val,size)           memset(dst,val,size)
#define yMemcpy(dst,src,size)           memcpy(dst,src,size)
#define yMemmove(dst,src,size)          memmove(dst,src,size)

#endif

#ifndef MICROCHIP_API
#include <stdarg.h>
#ifndef WINDOWS_API
#include <strings.h>
#endif
#endif

char *ystrdup_s(const char *src);
YRETCODE ystrcpy_s(char *dst, unsigned dstsize, const char *src);
YRETCODE ystrncpy_s(char *dst,unsigned dstsize,const char *src,unsigned len);
YRETCODE ystrcat_s(char *dst, unsigned dstsize,const char *src);
YRETCODE ystrncat_s(char *dst, unsigned dstsize,const char *src,unsigned len);
int ysprintf_s(char *dst, unsigned dstsize,const char *fmt ,...);
int yvsprintf_s (char *dst, unsigned dstsize, const char * fmt, va_list arg );
int ymemfind(const u8 *haystack, u32 haystack_len, const u8 *needle, u32 needle_len);



#if defined(WINDOWS_API) && defined(_MSC_VER) && !defined(WINCE)
    #define YSTRCMP(A,B)                        strcmp(A,B)
    #define YSTRNCMP(A,B,len)                   strncmp(A,B,len)
    #define YSTRICMP(A,B)                       _stricmp(A,B)
    #define YSTRNICMP(A,B,len)                  _strnicmp(A,B,len)
    #define YSTRLEN(str)                        ((int)strlen(str))
#elif defined(WINDOWS_API) && defined(__BORLANDC__)
    #define YSTRCMP(A,B)                        strcmp(A,B)
    #define YSTRNCMP(A,B,len)                   strncmp(A,B,len)
    #define YSTRICMP(A,B)                       strcmpi(A,B)
    #define YSTRNICMP(A,B,len)                  strncmpi(A,B,len)
    #define YSTRLEN(str)                        ((int)strlen(str))
#elif defined(WINCE)
    #define YSTRCMP(A,B)                        strcmp(A,B)
    #define YSTRNCMP(A,B,len)                   strncmp(A,B,len)
    #define YSTRICMP(A,B)                       _stricmp(A,B)
    #define YSTRNICMP(A,B,len)                  _strnicmp(A,B,len)
    #define YSTRLEN(str)                        ((int)strlen(str))
#else
    #define YSTRCMP(A,B)                        strcmp(A,B)
    #define YSTRNCMP(A,B,len)                   strncmp(A,B,len)
    #define YSTRICMP(A,B)                       strcasecmp(A,B)
    #define YSTRNICMP(A,B,len)                  strncasecmp(A,B,len)
    #define YSTRLEN(str)                        ((int)strlen(str))
#endif

#define YSTRDUP(src)                        ystrdup_s(src)
#define YSTRCPY(dst,dstsize,src)            ystrcpy_s(dst,dstsize,src)
#define YSTRCAT(dst,dstsize,src)            ystrcat_s(dst,dstsize,src)
#define YSTRNCAT(dst,dstsize,src,len)       ystrncat_s(dst,dstsize,src,len)
#define YSTRNCPY(dst,dstsize,src,len)       ystrncpy_s(dst,dstsize,src,len)
#define YSPRINTF                            ysprintf_s
#define YVSPRINTF                           yvsprintf_s


/**************************************************
 * Some redefintion of strxxx funtion.
 * we have base our code on the windows _s library
 * it seems a pain to put sizes everytime but it
 * can prevent some overflow and remove lots of
 * warnings during compilation
 ****************************************/
#ifdef __C30__

// Some string manipulation functions
#define itoa    forbidden_itoa__use_ys16toa_instead
#define uitoa   forbidden_uitoa_use_yu16toa_instead
#define ltoa    forbidden_itoa__use_ys32toa_instead
#define ultoa   forbidden_uitoa_use_yu32toa_instead
#define ys16toa(val,dst,dstsize)            s16toa(val, (char*)(dst))
#define yu16toa(val,dst,dstsize)            u16toa(val, (char*)(dst))
#define ys32toa(val,dst,dstsize)            s32toa(val, (char*)(dst))
#define yu32toa(val,dst,dstsize)            u32toa(val, (char*)(dst))
#define ystrcpy(dst,dstsize,src)            strcpy(dst,src)
#define ystrcat(dst,dstsize,src)            strcat(dst,src)
#define ystrncpy(dst,dstsize,src,len)       safestrcpy(dst,src,len)
//#define ysprintf(dst,dstsize,fmt,...)       ysprintf_should_not_be_used_in_PIC
#define ystrcmp(A,B)                        strcmp(A,B)
#define ystrncmp(A,B,len)                   strncmp(A,B,len)
#define ystricmp(A,B)                       stricmp(A,B)
#define ystrnicmp(A,B,len)                  strnicmp(A,B,len)
#define ystrlen(str)                        strlen(str)
#define ystrdup(str)                        strdup(str)
#else
#include <stdio.h>
#include <string.h>
// real OS -> map function to YAPI
#define ystrcpy(dst,dstsize,src)            YSTRCPY(dst,dstsize,src)
#define ystrcat(dst,dstsize,src)            YSTRCAT(dst,dstsize,src)
#define ystrncpy(dst,dstsize,src,len)       YSTRNCPY(dst,dstsize,src,len)
//#define ysprintf(dst,dstsize,fmt,...)       YSPRINTF(dst,dstsize,fmt,__VA_ARGS__)
#define ystrlen(str)                        ((u16)strlen(str))

#if defined(WINDOWS_API)
#define ys16toa(val,dst,dstsize)            _itoa_s((s32)(val),dst,dstsize,10)
#define yu16toa(val,dst,dstsize)            _itoa_s((u32)(val),dst,dstsize,10)
#define ys32toa(val,dst,dstsize)            _itoa_s((s32)(val),dst,dstsize,10)
#define yu32toa(val,dst,dstsize)            _ultoa_s((u32)(val),dst,dstsize,10)
#define ystrcmp(A,B)                        strcmp(A,B)
#define ystrncmp(A,B,len)                   strncmp(A,B,len)
#define ystricmp(A,B)                       _stricmp(A,B)
#define ystrnicmp(A,B,len)                  _strnicmp(A,B,len)
#define ylocaltime(res,time)                localtime_s(res,time)
#define ystrdup(str)                        _strdup(str)
#else
#define ys16toa(val,dst,dstsize)            sprintf(dst,"%d",val)
#define yu16toa(val,dst,dstsize)            sprintf(dst,"%u",val)
#define ys32toa(val,dst,dstsize)            sprintf(dst,"%d",val)
#define yu32toa(val,dst,dstsize)            sprintf(dst,"%u",val)
#define ystrcmp(A,B)                        strcmp(A,B)
#define ystrncmp(A,B,len)                   strncmp(A,B,len)
#define ystricmp(A,B)                       strcasecmp(A,B)
#define ystrnicmp(A,B,len)                  strncasecmp(A,B,len)
#define ystrdup(str)                        ystrdup_s(str)
#endif

#endif

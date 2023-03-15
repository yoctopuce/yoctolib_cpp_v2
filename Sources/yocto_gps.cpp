/*********************************************************************
 *
 *  $Id: yocto_gps.cpp 52570 2022-12-26 09:27:54Z seb $
 *
 *  Implements yFindGps(), the high-level API for Gps functions
 *
 *  - - - - - - - - - License information: - - - - - - - - -
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
 *  THE SOFTWARE AND DOCUMENTATION ARE PROVIDED 'AS IS' WITHOUT
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


#define _CRT_SECURE_NO_DEPRECATE //do not use windows secure crt
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>

#include "yocto_gps.h"
#include "yapi/yjson.h"
#include "yapi/yapi.h"
#define  __FILE_ID__  "gps"

#ifdef YOCTOLIB_NAMESPACE
using namespace YOCTOLIB_NAMESPACE;
#endif

YGps::YGps(const string& func): YFunction(func)
//--- (YGps initialization)
    ,_isFixed(ISFIXED_INVALID)
    ,_satCount(SATCOUNT_INVALID)
    ,_satPerConst(SATPERCONST_INVALID)
    ,_gpsRefreshRate(GPSREFRESHRATE_INVALID)
    ,_coordSystem(COORDSYSTEM_INVALID)
    ,_constellation(CONSTELLATION_INVALID)
    ,_latitude(LATITUDE_INVALID)
    ,_longitude(LONGITUDE_INVALID)
    ,_dilution(DILUTION_INVALID)
    ,_altitude(ALTITUDE_INVALID)
    ,_groundSpeed(GROUNDSPEED_INVALID)
    ,_direction(DIRECTION_INVALID)
    ,_unixTime(UNIXTIME_INVALID)
    ,_dateTime(DATETIME_INVALID)
    ,_utcOffset(UTCOFFSET_INVALID)
    ,_command(COMMAND_INVALID)
    ,_valueCallbackGps(NULL)
//--- (end of YGps initialization)
{
    _className="Gps";
}

YGps::~YGps()
{
//--- (YGps cleanup)
//--- (end of YGps cleanup)
}
//--- (YGps implementation)
// static attributes
const double YGps::GPSREFRESHRATE_INVALID = YAPI_INVALID_DOUBLE;
const string YGps::LATITUDE_INVALID = YAPI_INVALID_STRING;
const string YGps::LONGITUDE_INVALID = YAPI_INVALID_STRING;
const double YGps::DILUTION_INVALID = YAPI_INVALID_DOUBLE;
const double YGps::ALTITUDE_INVALID = YAPI_INVALID_DOUBLE;
const double YGps::GROUNDSPEED_INVALID = YAPI_INVALID_DOUBLE;
const double YGps::DIRECTION_INVALID = YAPI_INVALID_DOUBLE;
const string YGps::DATETIME_INVALID = YAPI_INVALID_STRING;
const string YGps::COMMAND_INVALID = YAPI_INVALID_STRING;

int YGps::_parseAttr(YJSONObject *json_val)
{
    if(json_val->has("isFixed")) {
        _isFixed =  (Y_ISFIXED_enum)json_val->getInt("isFixed");
    }
    if(json_val->has("satCount")) {
        _satCount =  json_val->getLong("satCount");
    }
    if(json_val->has("satPerConst")) {
        _satPerConst =  json_val->getLong("satPerConst");
    }
    if(json_val->has("gpsRefreshRate")) {
        _gpsRefreshRate =  floor(json_val->getDouble("gpsRefreshRate") / 65.536 + 0.5) / 1000.0;
    }
    if(json_val->has("coordSystem")) {
        _coordSystem =  (Y_COORDSYSTEM_enum)json_val->getInt("coordSystem");
    }
    if(json_val->has("constellation")) {
        _constellation =  (Y_CONSTELLATION_enum)json_val->getInt("constellation");
    }
    if(json_val->has("latitude")) {
        _latitude =  json_val->getString("latitude");
    }
    if(json_val->has("longitude")) {
        _longitude =  json_val->getString("longitude");
    }
    if(json_val->has("dilution")) {
        _dilution =  floor(json_val->getDouble("dilution") / 65.536 + 0.5) / 1000.0;
    }
    if(json_val->has("altitude")) {
        _altitude =  floor(json_val->getDouble("altitude") / 65.536 + 0.5) / 1000.0;
    }
    if(json_val->has("groundSpeed")) {
        _groundSpeed =  floor(json_val->getDouble("groundSpeed") / 65.536 + 0.5) / 1000.0;
    }
    if(json_val->has("direction")) {
        _direction =  floor(json_val->getDouble("direction") / 65.536 + 0.5) / 1000.0;
    }
    if(json_val->has("unixTime")) {
        _unixTime =  json_val->getLong("unixTime");
    }
    if(json_val->has("dateTime")) {
        _dateTime =  json_val->getString("dateTime");
    }
    if(json_val->has("utcOffset")) {
        _utcOffset =  json_val->getInt("utcOffset");
    }
    if(json_val->has("command")) {
        _command =  json_val->getString("command");
    }
    return YFunction::_parseAttr(json_val);
}


/**
 * Returns TRUE if the receiver has found enough satellites to work.
 *
 * @return either YGps::ISFIXED_FALSE or YGps::ISFIXED_TRUE, according to TRUE if the receiver has found
 * enough satellites to work
 *
 * On failure, throws an exception or returns YGps::ISFIXED_INVALID.
 */
Y_ISFIXED_enum YGps::get_isFixed(void)
{
    Y_ISFIXED_enum res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::ISFIXED_INVALID;
                }
            }
        }
        res = _isFixed;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the total count of satellites used to compute GPS position.
 *
 * @return an integer corresponding to the total count of satellites used to compute GPS position
 *
 * On failure, throws an exception or returns YGps::SATCOUNT_INVALID.
 */
s64 YGps::get_satCount(void)
{
    s64 res = 0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::SATCOUNT_INVALID;
                }
            }
        }
        res = _satCount;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the count of visible satellites per constellation encoded
 * on a 32 bit integer: bits 0..5: GPS satellites count,  bits 6..11 : Glonass, bits 12..17 : Galileo.
 * this value is refreshed every 5 seconds only.
 *
 * @return an integer corresponding to the count of visible satellites per constellation encoded
 *         on a 32 bit integer: bits 0.
 *
 * On failure, throws an exception or returns YGps::SATPERCONST_INVALID.
 */
s64 YGps::get_satPerConst(void)
{
    s64 res = 0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::SATPERCONST_INVALID;
                }
            }
        }
        res = _satPerConst;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns effective GPS data refresh frequency.
 * this value is refreshed every 5 seconds only.
 *
 * @return a floating point number corresponding to effective GPS data refresh frequency
 *
 * On failure, throws an exception or returns YGps::GPSREFRESHRATE_INVALID.
 */
double YGps::get_gpsRefreshRate(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::GPSREFRESHRATE_INVALID;
                }
            }
        }
        res = _gpsRefreshRate;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the representation system used for positioning data.
 *
 * @return a value among YGps::COORDSYSTEM_GPS_DMS, YGps::COORDSYSTEM_GPS_DM and YGps::COORDSYSTEM_GPS_D
 * corresponding to the representation system used for positioning data
 *
 * On failure, throws an exception or returns YGps::COORDSYSTEM_INVALID.
 */
Y_COORDSYSTEM_enum YGps::get_coordSystem(void)
{
    Y_COORDSYSTEM_enum res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::COORDSYSTEM_INVALID;
                }
            }
        }
        res = _coordSystem;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the representation system used for positioning data.
 * Remember to call the saveToFlash() method of the module if the
 * modification must be kept.
 *
 * @param newval : a value among YGps::COORDSYSTEM_GPS_DMS, YGps::COORDSYSTEM_GPS_DM and
 * YGps::COORDSYSTEM_GPS_D corresponding to the representation system used for positioning data
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YGps::set_coordSystem(Y_COORDSYSTEM_enum newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        char buf[32]; SAFE_SPRINTF(buf, 32, "%d", newval); rest_val = string(buf);
        res = _setAttr("coordSystem", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the the satellites constellation used to compute
 * positioning data.
 *
 * @return a value among YGps::CONSTELLATION_GNSS, YGps::CONSTELLATION_GPS, YGps::CONSTELLATION_GLONASS,
 * YGps::CONSTELLATION_GALILEO, YGps::CONSTELLATION_GPS_GLONASS, YGps::CONSTELLATION_GPS_GALILEO and
 * YGps::CONSTELLATION_GLONASS_GALILEO corresponding to the the satellites constellation used to compute
 *         positioning data
 *
 * On failure, throws an exception or returns YGps::CONSTELLATION_INVALID.
 */
Y_CONSTELLATION_enum YGps::get_constellation(void)
{
    Y_CONSTELLATION_enum res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::CONSTELLATION_INVALID;
                }
            }
        }
        res = _constellation;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the satellites constellation used to compute
 * positioning data. Possible  constellations are GNSS ( = all supported constellations),
 * GPS, Glonass, Galileo , and the 3 possible pairs. This setting has  no effect on Yocto-GPS (V1).
 *
 * @param newval : a value among YGps::CONSTELLATION_GNSS, YGps::CONSTELLATION_GPS,
 * YGps::CONSTELLATION_GLONASS, YGps::CONSTELLATION_GALILEO, YGps::CONSTELLATION_GPS_GLONASS,
 * YGps::CONSTELLATION_GPS_GALILEO and YGps::CONSTELLATION_GLONASS_GALILEO corresponding to the
 * satellites constellation used to compute
 *         positioning data
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YGps::set_constellation(Y_CONSTELLATION_enum newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        char buf[32]; SAFE_SPRINTF(buf, 32, "%d", newval); rest_val = string(buf);
        res = _setAttr("constellation", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the current latitude.
 *
 * @return a string corresponding to the current latitude
 *
 * On failure, throws an exception or returns YGps::LATITUDE_INVALID.
 */
string YGps::get_latitude(void)
{
    string res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::LATITUDE_INVALID;
                }
            }
        }
        res = _latitude;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the current longitude.
 *
 * @return a string corresponding to the current longitude
 *
 * On failure, throws an exception or returns YGps::LONGITUDE_INVALID.
 */
string YGps::get_longitude(void)
{
    string res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::LONGITUDE_INVALID;
                }
            }
        }
        res = _longitude;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the current horizontal dilution of precision,
 * the smaller that number is, the better .
 *
 * @return a floating point number corresponding to the current horizontal dilution of precision,
 *         the smaller that number is, the better
 *
 * On failure, throws an exception or returns YGps::DILUTION_INVALID.
 */
double YGps::get_dilution(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::DILUTION_INVALID;
                }
            }
        }
        res = _dilution;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the current altitude. Beware:  GPS technology
 * is very inaccurate regarding altitude.
 *
 * @return a floating point number corresponding to the current altitude
 *
 * On failure, throws an exception or returns YGps::ALTITUDE_INVALID.
 */
double YGps::get_altitude(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::ALTITUDE_INVALID;
                }
            }
        }
        res = _altitude;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the current ground speed in Km/h.
 *
 * @return a floating point number corresponding to the current ground speed in Km/h
 *
 * On failure, throws an exception or returns YGps::GROUNDSPEED_INVALID.
 */
double YGps::get_groundSpeed(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::GROUNDSPEED_INVALID;
                }
            }
        }
        res = _groundSpeed;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the current move bearing in degrees, zero
 * is the true (geographic) north.
 *
 * @return a floating point number corresponding to the current move bearing in degrees, zero
 *         is the true (geographic) north
 *
 * On failure, throws an exception or returns YGps::DIRECTION_INVALID.
 */
double YGps::get_direction(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::DIRECTION_INVALID;
                }
            }
        }
        res = _direction;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the current time in Unix format (number of
 * seconds elapsed since Jan 1st, 1970).
 *
 * @return an integer corresponding to the current time in Unix format (number of
 *         seconds elapsed since Jan 1st, 1970)
 *
 * On failure, throws an exception or returns YGps::UNIXTIME_INVALID.
 */
s64 YGps::get_unixTime(void)
{
    s64 res = 0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::UNIXTIME_INVALID;
                }
            }
        }
        res = _unixTime;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the current time in the form "YYYY/MM/DD hh:mm:ss".
 *
 * @return a string corresponding to the current time in the form "YYYY/MM/DD hh:mm:ss"
 *
 * On failure, throws an exception or returns YGps::DATETIME_INVALID.
 */
string YGps::get_dateTime(void)
{
    string res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::DATETIME_INVALID;
                }
            }
        }
        res = _dateTime;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the number of seconds between current time and UTC time (time zone).
 *
 * @return an integer corresponding to the number of seconds between current time and UTC time (time zone)
 *
 * On failure, throws an exception or returns YGps::UTCOFFSET_INVALID.
 */
int YGps::get_utcOffset(void)
{
    int res = 0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::UTCOFFSET_INVALID;
                }
            }
        }
        res = _utcOffset;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the number of seconds between current time and UTC time (time zone).
 * The timezone is automatically rounded to the nearest multiple of 15 minutes.
 * If current UTC time is known, the current time is automatically be updated according to the selected time zone.
 * Remember to call the saveToFlash() method of the module if the
 * modification must be kept.
 *
 * @param newval : an integer corresponding to the number of seconds between current time and UTC time (time zone)
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YGps::set_utcOffset(int newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        char buf[32]; SAFE_SPRINTF(buf, 32, "%d", newval); rest_val = string(buf);
        res = _setAttr("utcOffset", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

string YGps::get_command(void)
{
    string res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGps::COMMAND_INVALID;
                }
            }
        }
        res = _command;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

int YGps::set_command(const string& newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        rest_val = newval;
        res = _setAttr("command", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Retrieves a geolocalization module for a given identifier.
 * The identifier can be specified using several formats:
 * <ul>
 * <li>FunctionLogicalName</li>
 * <li>ModuleSerialNumber.FunctionIdentifier</li>
 * <li>ModuleSerialNumber.FunctionLogicalName</li>
 * <li>ModuleLogicalName.FunctionIdentifier</li>
 * <li>ModuleLogicalName.FunctionLogicalName</li>
 * </ul>
 *
 * This function does not require that the geolocalization module is online at the time
 * it is invoked. The returned object is nevertheless valid.
 * Use the method isOnline() to test if the geolocalization module is
 * indeed online at a given time. In case of ambiguity when looking for
 * a geolocalization module by logical name, no error is notified: the first instance
 * found is returned. The search is performed first by hardware name,
 * then by logical name.
 *
 * If a call to this object's is_online() method returns FALSE although
 * you are certain that the matching device is plugged, make sure that you did
 * call registerHub() at application initialization time.
 *
 * @param func : a string that uniquely characterizes the geolocalization module, for instance
 *         YGNSSMK2.gps.
 *
 * @return a YGps object allowing you to drive the geolocalization module.
 */
YGps* YGps::FindGps(string func)
{
    YGps* obj = NULL;
    int taken = 0;
    if (YAPI::_apiInitialized) {
        yEnterCriticalSection(&YAPI::_global_cs);
        taken = 1;
    }try {
        obj = (YGps*) YFunction::_FindFromCache("Gps", func);
        if (obj == NULL) {
            obj = new YGps(func);
            YFunction::_AddToCache("Gps", func, obj);
        }
    } catch (std::exception &) {
        if (taken) yLeaveCriticalSection(&YAPI::_global_cs);
        throw;
    }
    if (taken) yLeaveCriticalSection(&YAPI::_global_cs);
    return obj;
}

/**
 * Registers the callback function that is invoked on every change of advertised value.
 * The callback is invoked only during the execution of ySleep or yHandleEvents.
 * This provides control over the time when the callback is triggered. For good responsiveness, remember to call
 * one of these two functions periodically. To unregister a callback, pass a NULL pointer as argument.
 *
 * @param callback : the callback function to call, or a NULL pointer. The callback function should take two
 *         arguments: the function object of which the value has changed, and the character string describing
 *         the new advertised value.
 * @noreturn
 */
int YGps::registerValueCallback(YGpsValueCallback callback)
{
    string val;
    if (callback != NULL) {
        YFunction::_UpdateValueCallbackList(this, true);
    } else {
        YFunction::_UpdateValueCallbackList(this, false);
    }
    _valueCallbackGps = callback;
    // Immediately invoke value callback with current value
    if (callback != NULL && this->isOnline()) {
        val = _advertisedValue;
        if (!(val == "")) {
            this->_invokeValueCallback(val);
        }
    }
    return 0;
}

int YGps::_invokeValueCallback(string value)
{
    if (_valueCallbackGps != NULL) {
        _valueCallbackGps(this, value);
    } else {
        YFunction::_invokeValueCallback(value);
    }
    return 0;
}

YGps *YGps::nextGps(void)
{
    string  hwid;

    if(YISERR(_nextFunction(hwid)) || hwid=="") {
        return NULL;
    }
    return YGps::FindGps(hwid);
}

YGps *YGps::FirstGps(void)
{
    vector<YFUN_DESCR>   v_fundescr;
    YDEV_DESCR             ydevice;
    string              serial, funcId, funcName, funcVal, errmsg;

    if(YISERR(YapiWrapper::getFunctionsByClass("Gps", 0, v_fundescr, sizeof(YFUN_DESCR), errmsg)) ||
       v_fundescr.size() == 0 ||
       YISERR(YapiWrapper::getFunctionInfo(v_fundescr[0], ydevice, serial, funcId, funcName, funcVal, errmsg))) {
        return NULL;
    }
    return YGps::FindGps(serial+"."+funcId);
}

//--- (end of YGps implementation)

//--- (YGps functions)
//--- (end of YGps functions)

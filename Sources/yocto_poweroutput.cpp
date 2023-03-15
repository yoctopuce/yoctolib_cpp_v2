/*********************************************************************
 *
 *  $Id: yocto_poweroutput.cpp 52570 2022-12-26 09:27:54Z seb $
 *
 *  Implements yFindPowerOutput(), the high-level API for PowerOutput functions
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

#include "yocto_poweroutput.h"
#include "yapi/yjson.h"
#include "yapi/yapi.h"
#define  __FILE_ID__  "poweroutput"

#ifdef YOCTOLIB_NAMESPACE
using namespace YOCTOLIB_NAMESPACE;
#endif

YPowerOutput::YPowerOutput(const string& func): YFunction(func)
//--- (YPowerOutput initialization)
    ,_voltage(VOLTAGE_INVALID)
    ,_valueCallbackPowerOutput(NULL)
//--- (end of YPowerOutput initialization)
{
    _className="PowerOutput";
}

YPowerOutput::~YPowerOutput()
{
//--- (YPowerOutput cleanup)
//--- (end of YPowerOutput cleanup)
}
//--- (YPowerOutput implementation)
// static attributes

int YPowerOutput::_parseAttr(YJSONObject *json_val)
{
    if(json_val->has("voltage")) {
        _voltage =  (Y_VOLTAGE_enum)json_val->getInt("voltage");
    }
    return YFunction::_parseAttr(json_val);
}


/**
 * Returns the voltage on the power output featured by the module.
 *
 * @return a value among YPowerOutput::VOLTAGE_OFF, YPowerOutput::VOLTAGE_OUT3V3,
 * YPowerOutput::VOLTAGE_OUT5V, YPowerOutput::VOLTAGE_OUT4V7 and YPowerOutput::VOLTAGE_OUT1V8
 * corresponding to the voltage on the power output featured by the module
 *
 * On failure, throws an exception or returns YPowerOutput::VOLTAGE_INVALID.
 */
Y_VOLTAGE_enum YPowerOutput::get_voltage(void)
{
    Y_VOLTAGE_enum res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YPowerOutput::VOLTAGE_INVALID;
                }
            }
        }
        res = _voltage;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the voltage on the power output provided by the
 * module. Remember to call the saveToFlash() method of the module if the
 * modification must be kept.
 *
 * @param newval : a value among YPowerOutput::VOLTAGE_OFF, YPowerOutput::VOLTAGE_OUT3V3,
 * YPowerOutput::VOLTAGE_OUT5V, YPowerOutput::VOLTAGE_OUT4V7 and YPowerOutput::VOLTAGE_OUT1V8
 * corresponding to the voltage on the power output provided by the
 *         module
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPowerOutput::set_voltage(Y_VOLTAGE_enum newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        char buf[32]; SAFE_SPRINTF(buf, 32, "%d", newval); rest_val = string(buf);
        res = _setAttr("voltage", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Retrieves a power output for a given identifier.
 * The identifier can be specified using several formats:
 * <ul>
 * <li>FunctionLogicalName</li>
 * <li>ModuleSerialNumber.FunctionIdentifier</li>
 * <li>ModuleSerialNumber.FunctionLogicalName</li>
 * <li>ModuleLogicalName.FunctionIdentifier</li>
 * <li>ModuleLogicalName.FunctionLogicalName</li>
 * </ul>
 *
 * This function does not require that the power output is online at the time
 * it is invoked. The returned object is nevertheless valid.
 * Use the method isOnline() to test if the power output is
 * indeed online at a given time. In case of ambiguity when looking for
 * a power output by logical name, no error is notified: the first instance
 * found is returned. The search is performed first by hardware name,
 * then by logical name.
 *
 * If a call to this object's is_online() method returns FALSE although
 * you are certain that the matching device is plugged, make sure that you did
 * call registerHub() at application initialization time.
 *
 * @param func : a string that uniquely characterizes the power output, for instance
 *         YI2CMK01.powerOutput.
 *
 * @return a YPowerOutput object allowing you to drive the power output.
 */
YPowerOutput* YPowerOutput::FindPowerOutput(string func)
{
    YPowerOutput* obj = NULL;
    int taken = 0;
    if (YAPI::_apiInitialized) {
        yEnterCriticalSection(&YAPI::_global_cs);
        taken = 1;
    }try {
        obj = (YPowerOutput*) YFunction::_FindFromCache("PowerOutput", func);
        if (obj == NULL) {
            obj = new YPowerOutput(func);
            YFunction::_AddToCache("PowerOutput", func, obj);
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
int YPowerOutput::registerValueCallback(YPowerOutputValueCallback callback)
{
    string val;
    if (callback != NULL) {
        YFunction::_UpdateValueCallbackList(this, true);
    } else {
        YFunction::_UpdateValueCallbackList(this, false);
    }
    _valueCallbackPowerOutput = callback;
    // Immediately invoke value callback with current value
    if (callback != NULL && this->isOnline()) {
        val = _advertisedValue;
        if (!(val == "")) {
            this->_invokeValueCallback(val);
        }
    }
    return 0;
}

int YPowerOutput::_invokeValueCallback(string value)
{
    if (_valueCallbackPowerOutput != NULL) {
        _valueCallbackPowerOutput(this, value);
    } else {
        YFunction::_invokeValueCallback(value);
    }
    return 0;
}

YPowerOutput *YPowerOutput::nextPowerOutput(void)
{
    string  hwid;

    if(YISERR(_nextFunction(hwid)) || hwid=="") {
        return NULL;
    }
    return YPowerOutput::FindPowerOutput(hwid);
}

YPowerOutput *YPowerOutput::FirstPowerOutput(void)
{
    vector<YFUN_DESCR>   v_fundescr;
    YDEV_DESCR             ydevice;
    string              serial, funcId, funcName, funcVal, errmsg;

    if(YISERR(YapiWrapper::getFunctionsByClass("PowerOutput", 0, v_fundescr, sizeof(YFUN_DESCR), errmsg)) ||
       v_fundescr.size() == 0 ||
       YISERR(YapiWrapper::getFunctionInfo(v_fundescr[0], ydevice, serial, funcId, funcName, funcVal, errmsg))) {
        return NULL;
    }
    return YPowerOutput::FindPowerOutput(serial+"."+funcId);
}

//--- (end of YPowerOutput implementation)

//--- (YPowerOutput functions)
//--- (end of YPowerOutput functions)

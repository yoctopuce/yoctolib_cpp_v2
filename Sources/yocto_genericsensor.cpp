/*********************************************************************
 *
 *  $Id: yocto_genericsensor.cpp 52570 2022-12-26 09:27:54Z seb $
 *
 *  Implements yFindGenericSensor(), the high-level API for GenericSensor functions
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

#include "yocto_genericsensor.h"
#include "yapi/yjson.h"
#include "yapi/yapi.h"
#define  __FILE_ID__  "genericsensor"

#ifdef YOCTOLIB_NAMESPACE
using namespace YOCTOLIB_NAMESPACE;
#endif

YGenericSensor::YGenericSensor(const string& func): YSensor(func)
//--- (YGenericSensor initialization)
    ,_signalValue(SIGNALVALUE_INVALID)
    ,_signalUnit(SIGNALUNIT_INVALID)
    ,_signalRange(SIGNALRANGE_INVALID)
    ,_valueRange(VALUERANGE_INVALID)
    ,_signalBias(SIGNALBIAS_INVALID)
    ,_signalSampling(SIGNALSAMPLING_INVALID)
    ,_enabled(ENABLED_INVALID)
    ,_valueCallbackGenericSensor(NULL)
    ,_timedReportCallbackGenericSensor(NULL)
//--- (end of YGenericSensor initialization)
{
    _className="GenericSensor";
}

YGenericSensor::~YGenericSensor()
{
//--- (YGenericSensor cleanup)
//--- (end of YGenericSensor cleanup)
}
//--- (YGenericSensor implementation)
// static attributes
const double YGenericSensor::SIGNALVALUE_INVALID = YAPI_INVALID_DOUBLE;
const string YGenericSensor::SIGNALUNIT_INVALID = YAPI_INVALID_STRING;
const string YGenericSensor::SIGNALRANGE_INVALID = YAPI_INVALID_STRING;
const string YGenericSensor::VALUERANGE_INVALID = YAPI_INVALID_STRING;
const double YGenericSensor::SIGNALBIAS_INVALID = YAPI_INVALID_DOUBLE;

int YGenericSensor::_parseAttr(YJSONObject *json_val)
{
    if(json_val->has("signalValue")) {
        _signalValue =  floor(json_val->getDouble("signalValue") / 65.536 + 0.5) / 1000.0;
    }
    if(json_val->has("signalUnit")) {
        _signalUnit =  json_val->getString("signalUnit");
    }
    if(json_val->has("signalRange")) {
        _signalRange =  json_val->getString("signalRange");
    }
    if(json_val->has("valueRange")) {
        _valueRange =  json_val->getString("valueRange");
    }
    if(json_val->has("signalBias")) {
        _signalBias =  floor(json_val->getDouble("signalBias") / 65.536 + 0.5) / 1000.0;
    }
    if(json_val->has("signalSampling")) {
        _signalSampling =  (Y_SIGNALSAMPLING_enum)json_val->getInt("signalSampling");
    }
    if(json_val->has("enabled")) {
        _enabled =  (Y_ENABLED_enum)json_val->getInt("enabled");
    }
    return YSensor::_parseAttr(json_val);
}


/**
 * Changes the measuring unit for the measured value.
 * Remember to call the saveToFlash() method of the module if the
 * modification must be kept.
 *
 * @param newval : a string corresponding to the measuring unit for the measured value
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YGenericSensor::set_unit(const string& newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        rest_val = newval;
        res = _setAttr("unit", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the current value of the electrical signal measured by the sensor.
 *
 * @return a floating point number corresponding to the current value of the electrical signal
 * measured by the sensor
 *
 * On failure, throws an exception or returns YGenericSensor::SIGNALVALUE_INVALID.
 */
double YGenericSensor::get_signalValue(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGenericSensor::SIGNALVALUE_INVALID;
                }
            }
        }
        res = floor(_signalValue * 1000+0.5) / 1000;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the measuring unit of the electrical signal used by the sensor.
 *
 * @return a string corresponding to the measuring unit of the electrical signal used by the sensor
 *
 * On failure, throws an exception or returns YGenericSensor::SIGNALUNIT_INVALID.
 */
string YGenericSensor::get_signalUnit(void)
{
    string res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration == 0) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGenericSensor::SIGNALUNIT_INVALID;
                }
            }
        }
        res = _signalUnit;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the input signal range used by the sensor.
 *
 * @return a string corresponding to the input signal range used by the sensor
 *
 * On failure, throws an exception or returns YGenericSensor::SIGNALRANGE_INVALID.
 */
string YGenericSensor::get_signalRange(void)
{
    string res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGenericSensor::SIGNALRANGE_INVALID;
                }
            }
        }
        res = _signalRange;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the input signal range used by the sensor.
 * When the input signal gets out of the planned range, the output value
 * will be set to an arbitrary large value, whose sign indicates the direction
 * of the range overrun.
 *
 * For a 4-20mA sensor, the default input signal range is "4...20".
 * For a 0-10V sensor, the default input signal range is "0.1...10".
 * For numeric communication interfaces, the default input signal range is
 * "-999999.999...999999.999".
 *
 * Remember to call the saveToFlash()
 * method of the module if the modification must be kept.
 *
 * @param newval : a string corresponding to the input signal range used by the sensor
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YGenericSensor::set_signalRange(const string& newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        rest_val = newval;
        res = _setAttr("signalRange", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the physical value range measured by the sensor.
 *
 * @return a string corresponding to the physical value range measured by the sensor
 *
 * On failure, throws an exception or returns YGenericSensor::VALUERANGE_INVALID.
 */
string YGenericSensor::get_valueRange(void)
{
    string res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGenericSensor::VALUERANGE_INVALID;
                }
            }
        }
        res = _valueRange;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the output value range, corresponding to the physical value measured
 * by the sensor. The default output value range is the same as the input signal
 * range (1:1 mapping), but you can change it so that the function automatically
 * computes the physical value encoded by the input signal. Be aware that, as a
 * side effect, the range modification may automatically modify the display resolution.
 *
 * Remember to call the saveToFlash()
 * method of the module if the modification must be kept.
 *
 * @param newval : a string corresponding to the output value range, corresponding to the physical value measured
 *         by the sensor
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YGenericSensor::set_valueRange(const string& newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        rest_val = newval;
        res = _setAttr("valueRange", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the electric signal bias for zero shift adjustment.
 * If your electric signal reads positive when it should be zero, setup
 * a positive signalBias of the same value to fix the zero shift.
 * Remember to call the saveToFlash()
 * method of the module if the modification must be kept.
 *
 * @param newval : a floating point number corresponding to the electric signal bias for zero shift adjustment
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YGenericSensor::set_signalBias(double newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        char buf[32]; SAFE_SPRINTF(buf, 32, "%" FMTs64, (s64)floor(newval * 65536.0 + 0.5)); rest_val = string(buf);
        res = _setAttr("signalBias", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the electric signal bias for zero shift adjustment.
 * A positive bias means that the signal is over-reporting the measure,
 * while a negative bias means that the signal is under-reporting the measure.
 *
 * @return a floating point number corresponding to the electric signal bias for zero shift adjustment
 *
 * On failure, throws an exception or returns YGenericSensor::SIGNALBIAS_INVALID.
 */
double YGenericSensor::get_signalBias(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGenericSensor::SIGNALBIAS_INVALID;
                }
            }
        }
        res = _signalBias;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the electric signal sampling method to use.
 * The HIGH_RATE method uses the highest sampling frequency, without any filtering.
 * The HIGH_RATE_FILTERED method adds a windowed 7-sample median filter.
 * The LOW_NOISE method uses a reduced acquisition frequency to reduce noise.
 * The LOW_NOISE_FILTERED method combines a reduced frequency with the median filter
 * to get measures as stable as possible when working on a noisy signal.
 *
 * @return a value among YGenericSensor::SIGNALSAMPLING_HIGH_RATE,
 * YGenericSensor::SIGNALSAMPLING_HIGH_RATE_FILTERED, YGenericSensor::SIGNALSAMPLING_LOW_NOISE,
 * YGenericSensor::SIGNALSAMPLING_LOW_NOISE_FILTERED, YGenericSensor::SIGNALSAMPLING_HIGHEST_RATE and
 * YGenericSensor::SIGNALSAMPLING_AC corresponding to the electric signal sampling method to use
 *
 * On failure, throws an exception or returns YGenericSensor::SIGNALSAMPLING_INVALID.
 */
Y_SIGNALSAMPLING_enum YGenericSensor::get_signalSampling(void)
{
    Y_SIGNALSAMPLING_enum res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGenericSensor::SIGNALSAMPLING_INVALID;
                }
            }
        }
        res = _signalSampling;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the electric signal sampling method to use.
 * The HIGH_RATE method uses the highest sampling frequency, without any filtering.
 * The HIGH_RATE_FILTERED method adds a windowed 7-sample median filter.
 * The LOW_NOISE method uses a reduced acquisition frequency to reduce noise.
 * The LOW_NOISE_FILTERED method combines a reduced frequency with the median filter
 * to get measures as stable as possible when working on a noisy signal.
 * Remember to call the saveToFlash()
 * method of the module if the modification must be kept.
 *
 * @param newval : a value among YGenericSensor::SIGNALSAMPLING_HIGH_RATE,
 * YGenericSensor::SIGNALSAMPLING_HIGH_RATE_FILTERED, YGenericSensor::SIGNALSAMPLING_LOW_NOISE,
 * YGenericSensor::SIGNALSAMPLING_LOW_NOISE_FILTERED, YGenericSensor::SIGNALSAMPLING_HIGHEST_RATE and
 * YGenericSensor::SIGNALSAMPLING_AC corresponding to the electric signal sampling method to use
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YGenericSensor::set_signalSampling(Y_SIGNALSAMPLING_enum newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        char buf[32]; SAFE_SPRINTF(buf, 32, "%d", newval); rest_val = string(buf);
        res = _setAttr("signalSampling", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the activation state of this input.
 *
 * @return either YGenericSensor::ENABLED_FALSE or YGenericSensor::ENABLED_TRUE, according to the
 * activation state of this input
 *
 * On failure, throws an exception or returns YGenericSensor::ENABLED_INVALID.
 */
Y_ENABLED_enum YGenericSensor::get_enabled(void)
{
    Y_ENABLED_enum res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YGenericSensor::ENABLED_INVALID;
                }
            }
        }
        res = _enabled;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the activation state of this input. When an input is disabled,
 * its value is no more updated. On some devices, disabling an input can
 * improve the refresh rate of the other active inputs.
 * Remember to call the saveToFlash()
 * method of the module if the modification must be kept.
 *
 * @param newval : either YGenericSensor::ENABLED_FALSE or YGenericSensor::ENABLED_TRUE, according to
 * the activation state of this input
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YGenericSensor::set_enabled(Y_ENABLED_enum newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        rest_val = (newval>0 ? "1" : "0");
        res = _setAttr("enabled", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Retrieves a generic sensor for a given identifier.
 * The identifier can be specified using several formats:
 * <ul>
 * <li>FunctionLogicalName</li>
 * <li>ModuleSerialNumber.FunctionIdentifier</li>
 * <li>ModuleSerialNumber.FunctionLogicalName</li>
 * <li>ModuleLogicalName.FunctionIdentifier</li>
 * <li>ModuleLogicalName.FunctionLogicalName</li>
 * </ul>
 *
 * This function does not require that the generic sensor is online at the time
 * it is invoked. The returned object is nevertheless valid.
 * Use the method isOnline() to test if the generic sensor is
 * indeed online at a given time. In case of ambiguity when looking for
 * a generic sensor by logical name, no error is notified: the first instance
 * found is returned. The search is performed first by hardware name,
 * then by logical name.
 *
 * If a call to this object's is_online() method returns FALSE although
 * you are certain that the matching device is plugged, make sure that you did
 * call registerHub() at application initialization time.
 *
 * @param func : a string that uniquely characterizes the generic sensor, for instance
 *         RX010V01.genericSensor1.
 *
 * @return a YGenericSensor object allowing you to drive the generic sensor.
 */
YGenericSensor* YGenericSensor::FindGenericSensor(string func)
{
    YGenericSensor* obj = NULL;
    int taken = 0;
    if (YAPI::_apiInitialized) {
        yEnterCriticalSection(&YAPI::_global_cs);
        taken = 1;
    }try {
        obj = (YGenericSensor*) YFunction::_FindFromCache("GenericSensor", func);
        if (obj == NULL) {
            obj = new YGenericSensor(func);
            YFunction::_AddToCache("GenericSensor", func, obj);
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
int YGenericSensor::registerValueCallback(YGenericSensorValueCallback callback)
{
    string val;
    if (callback != NULL) {
        YFunction::_UpdateValueCallbackList(this, true);
    } else {
        YFunction::_UpdateValueCallbackList(this, false);
    }
    _valueCallbackGenericSensor = callback;
    // Immediately invoke value callback with current value
    if (callback != NULL && this->isOnline()) {
        val = _advertisedValue;
        if (!(val == "")) {
            this->_invokeValueCallback(val);
        }
    }
    return 0;
}

int YGenericSensor::_invokeValueCallback(string value)
{
    if (_valueCallbackGenericSensor != NULL) {
        _valueCallbackGenericSensor(this, value);
    } else {
        YSensor::_invokeValueCallback(value);
    }
    return 0;
}

/**
 * Registers the callback function that is invoked on every periodic timed notification.
 * The callback is invoked only during the execution of ySleep or yHandleEvents.
 * This provides control over the time when the callback is triggered. For good responsiveness, remember to call
 * one of these two functions periodically. To unregister a callback, pass a NULL pointer as argument.
 *
 * @param callback : the callback function to call, or a NULL pointer. The callback function should take two
 *         arguments: the function object of which the value has changed, and an YMeasure object describing
 *         the new advertised value.
 * @noreturn
 */
int YGenericSensor::registerTimedReportCallback(YGenericSensorTimedReportCallback callback)
{
    YSensor* sensor = NULL;
    sensor = this;
    if (callback != NULL) {
        YFunction::_UpdateTimedReportCallbackList(sensor, true);
    } else {
        YFunction::_UpdateTimedReportCallbackList(sensor, false);
    }
    _timedReportCallbackGenericSensor = callback;
    return 0;
}

int YGenericSensor::_invokeTimedReportCallback(YMeasure value)
{
    if (_timedReportCallbackGenericSensor != NULL) {
        _timedReportCallbackGenericSensor(this, value);
    } else {
        YSensor::_invokeTimedReportCallback(value);
    }
    return 0;
}

/**
 * Adjusts the signal bias so that the current signal value is need
 * precisely as zero. Remember to call the saveToFlash()
 * method of the module if the modification must be kept.
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YGenericSensor::zeroAdjust(void)
{
    double currSignal = 0.0;
    double currBias = 0.0;
    currSignal = this->get_signalValue();
    currBias = this->get_signalBias();
    return this->set_signalBias(currSignal + currBias);
}

YGenericSensor *YGenericSensor::nextGenericSensor(void)
{
    string  hwid;

    if(YISERR(_nextFunction(hwid)) || hwid=="") {
        return NULL;
    }
    return YGenericSensor::FindGenericSensor(hwid);
}

YGenericSensor *YGenericSensor::FirstGenericSensor(void)
{
    vector<YFUN_DESCR>   v_fundescr;
    YDEV_DESCR             ydevice;
    string              serial, funcId, funcName, funcVal, errmsg;

    if(YISERR(YapiWrapper::getFunctionsByClass("GenericSensor", 0, v_fundescr, sizeof(YFUN_DESCR), errmsg)) ||
       v_fundescr.size() == 0 ||
       YISERR(YapiWrapper::getFunctionInfo(v_fundescr[0], ydevice, serial, funcId, funcName, funcVal, errmsg))) {
        return NULL;
    }
    return YGenericSensor::FindGenericSensor(serial+"."+funcId);
}

//--- (end of YGenericSensor implementation)

//--- (YGenericSensor functions)
//--- (end of YGenericSensor functions)

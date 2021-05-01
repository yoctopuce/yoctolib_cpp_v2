/*********************************************************************
 *
 *  $Id: yocto_pwmoutput.cpp 44049 2021-02-26 10:57:40Z web $
 *
 *  Implements yFindPwmOutput(), the high-level API for PwmOutput functions
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

#include "yocto_pwmoutput.h"
#include "yapi/yjson.h"
#include "yapi/yapi.h"
#define  __FILE_ID__  "pwmoutput"

#ifdef YOCTOLIB_NAMESPACE
using namespace YOCTOLIB_NAMESPACE;
#endif

YPwmOutput::YPwmOutput(const string& func): YFunction(func)
//--- (YPwmOutput initialization)
    ,_enabled(ENABLED_INVALID)
    ,_frequency(FREQUENCY_INVALID)
    ,_period(PERIOD_INVALID)
    ,_dutyCycle(DUTYCYCLE_INVALID)
    ,_pulseDuration(PULSEDURATION_INVALID)
    ,_pwmTransition(PWMTRANSITION_INVALID)
    ,_enabledAtPowerOn(ENABLEDATPOWERON_INVALID)
    ,_dutyCycleAtPowerOn(DUTYCYCLEATPOWERON_INVALID)
    ,_valueCallbackPwmOutput(NULL)
//--- (end of YPwmOutput initialization)
{
    _className="PwmOutput";
}

YPwmOutput::~YPwmOutput()
{
//--- (YPwmOutput cleanup)
//--- (end of YPwmOutput cleanup)
}
//--- (YPwmOutput implementation)
// static attributes
const double YPwmOutput::FREQUENCY_INVALID = YAPI_INVALID_DOUBLE;
const double YPwmOutput::PERIOD_INVALID = YAPI_INVALID_DOUBLE;
const double YPwmOutput::DUTYCYCLE_INVALID = YAPI_INVALID_DOUBLE;
const double YPwmOutput::PULSEDURATION_INVALID = YAPI_INVALID_DOUBLE;
const string YPwmOutput::PWMTRANSITION_INVALID = YAPI_INVALID_STRING;
const double YPwmOutput::DUTYCYCLEATPOWERON_INVALID = YAPI_INVALID_DOUBLE;

int YPwmOutput::_parseAttr(YJSONObject *json_val)
{
    if(json_val->has("enabled")) {
        _enabled =  (Y_ENABLED_enum)json_val->getInt("enabled");
    }
    if(json_val->has("frequency")) {
        _frequency =  floor(json_val->getDouble("frequency") * 1000.0 / 65536.0 + 0.5) / 1000.0;
    }
    if(json_val->has("period")) {
        _period =  floor(json_val->getDouble("period") * 1000.0 / 65536.0 + 0.5) / 1000.0;
    }
    if(json_val->has("dutyCycle")) {
        _dutyCycle =  floor(json_val->getDouble("dutyCycle") * 1000.0 / 65536.0 + 0.5) / 1000.0;
    }
    if(json_val->has("pulseDuration")) {
        _pulseDuration =  floor(json_val->getDouble("pulseDuration") * 1000.0 / 65536.0 + 0.5) / 1000.0;
    }
    if(json_val->has("pwmTransition")) {
        _pwmTransition =  json_val->getString("pwmTransition");
    }
    if(json_val->has("enabledAtPowerOn")) {
        _enabledAtPowerOn =  (Y_ENABLEDATPOWERON_enum)json_val->getInt("enabledAtPowerOn");
    }
    if(json_val->has("dutyCycleAtPowerOn")) {
        _dutyCycleAtPowerOn =  floor(json_val->getDouble("dutyCycleAtPowerOn") * 1000.0 / 65536.0 + 0.5) / 1000.0;
    }
    return YFunction::_parseAttr(json_val);
}


/**
 * Returns the state of the PWM generators.
 *
 * @return either YPwmOutput::ENABLED_FALSE or YPwmOutput::ENABLED_TRUE, according to the state of the PWM generators
 *
 * On failure, throws an exception or returns YPwmOutput::ENABLED_INVALID.
 */
Y_ENABLED_enum YPwmOutput::get_enabled(void)
{
    Y_ENABLED_enum res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YPwmOutput::ENABLED_INVALID;
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
 * Stops or starts the PWM.
 *
 * @param newval : either YPwmOutput::ENABLED_FALSE or YPwmOutput::ENABLED_TRUE
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::set_enabled(Y_ENABLED_enum newval)
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
 * Changes the PWM frequency. The duty cycle is kept unchanged thanks to an
 * automatic pulse width change, in other words, the change will not be applied
 * before the end of the current period. This can significantly affect reaction
 * time at low frequencies. If you call the matching module saveToFlash()
 * method, the frequency will be kept after a device power cycle.
 * To stop the PWM signal, do not set the frequency to zero, use the set_enabled()
 * method instead.
 *
 * @param newval : a floating point number corresponding to the PWM frequency
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::set_frequency(double newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        char buf[32]; sprintf(buf, "%" FMTs64, (s64)floor(newval * 65536.0 + 0.5)); rest_val = string(buf);
        res = _setAttr("frequency", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the PWM frequency in Hz.
 *
 * @return a floating point number corresponding to the PWM frequency in Hz
 *
 * On failure, throws an exception or returns YPwmOutput::FREQUENCY_INVALID.
 */
double YPwmOutput::get_frequency(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YPwmOutput::FREQUENCY_INVALID;
                }
            }
        }
        res = _frequency;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the PWM period in milliseconds. Caution: in order to avoid  random truncation of
 * the current pulse, the change will not be applied
 * before the end of the current period. This can significantly affect reaction
 * time at low frequencies. If you call the matching module saveToFlash()
 * method, the frequency will be kept after a device power cycle.
 *
 * @param newval : a floating point number corresponding to the PWM period in milliseconds
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::set_period(double newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        char buf[32]; sprintf(buf, "%" FMTs64, (s64)floor(newval * 65536.0 + 0.5)); rest_val = string(buf);
        res = _setAttr("period", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the PWM period in milliseconds.
 *
 * @return a floating point number corresponding to the PWM period in milliseconds
 *
 * On failure, throws an exception or returns YPwmOutput::PERIOD_INVALID.
 */
double YPwmOutput::get_period(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YPwmOutput::PERIOD_INVALID;
                }
            }
        }
        res = _period;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the PWM duty cycle, in per cents.
 *
 * @param newval : a floating point number corresponding to the PWM duty cycle, in per cents
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::set_dutyCycle(double newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        char buf[32]; sprintf(buf, "%" FMTs64, (s64)floor(newval * 65536.0 + 0.5)); rest_val = string(buf);
        res = _setAttr("dutyCycle", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the PWM duty cycle, in per cents.
 *
 * @return a floating point number corresponding to the PWM duty cycle, in per cents
 *
 * On failure, throws an exception or returns YPwmOutput::DUTYCYCLE_INVALID.
 */
double YPwmOutput::get_dutyCycle(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YPwmOutput::DUTYCYCLE_INVALID;
                }
            }
        }
        res = _dutyCycle;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the PWM pulse length, in milliseconds. A pulse length cannot be longer than period,
 * otherwise it is truncated.
 *
 * @param newval : a floating point number corresponding to the PWM pulse length, in milliseconds
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::set_pulseDuration(double newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        char buf[32]; sprintf(buf, "%" FMTs64, (s64)floor(newval * 65536.0 + 0.5)); rest_val = string(buf);
        res = _setAttr("pulseDuration", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the PWM pulse length in milliseconds, as a floating point number.
 *
 * @return a floating point number corresponding to the PWM pulse length in milliseconds, as a
 * floating point number
 *
 * On failure, throws an exception or returns YPwmOutput::PULSEDURATION_INVALID.
 */
double YPwmOutput::get_pulseDuration(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YPwmOutput::PULSEDURATION_INVALID;
                }
            }
        }
        res = _pulseDuration;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

string YPwmOutput::get_pwmTransition(void)
{
    string res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YPwmOutput::PWMTRANSITION_INVALID;
                }
            }
        }
        res = _pwmTransition;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

int YPwmOutput::set_pwmTransition(const string& newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        rest_val = newval;
        res = _setAttr("pwmTransition", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the state of the PWM at device power on.
 *
 * @return either YPwmOutput::ENABLEDATPOWERON_FALSE or YPwmOutput::ENABLEDATPOWERON_TRUE, according to
 * the state of the PWM at device power on
 *
 * On failure, throws an exception or returns YPwmOutput::ENABLEDATPOWERON_INVALID.
 */
Y_ENABLEDATPOWERON_enum YPwmOutput::get_enabledAtPowerOn(void)
{
    Y_ENABLEDATPOWERON_enum res;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YPwmOutput::ENABLEDATPOWERON_INVALID;
                }
            }
        }
        res = _enabledAtPowerOn;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the state of the PWM at device power on. Remember to call the matching module saveToFlash()
 * method, otherwise this call will have no effect.
 *
 * @param newval : either YPwmOutput::ENABLEDATPOWERON_FALSE or YPwmOutput::ENABLEDATPOWERON_TRUE,
 * according to the state of the PWM at device power on
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::set_enabledAtPowerOn(Y_ENABLEDATPOWERON_enum newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        rest_val = (newval>0 ? "1" : "0");
        res = _setAttr("enabledAtPowerOn", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Changes the PWM duty cycle at device power on. Remember to call the matching
 * module saveToFlash() method, otherwise this call will have no effect.
 *
 * @param newval : a floating point number corresponding to the PWM duty cycle at device power on
 *
 * @return YAPI::SUCCESS if the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::set_dutyCycleAtPowerOn(double newval)
{
    string rest_val;
    int res;
    yEnterCriticalSection(&_this_cs);
    try {
        char buf[32]; sprintf(buf, "%" FMTs64, (s64)floor(newval * 65536.0 + 0.5)); rest_val = string(buf);
        res = _setAttr("dutyCycleAtPowerOn", rest_val);
    } catch (std::exception &) {
         yLeaveCriticalSection(&_this_cs);
         throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Returns the PWM generators duty cycle at device power on as a floating point number between 0 and 100.
 *
 * @return a floating point number corresponding to the PWM generators duty cycle at device power on
 * as a floating point number between 0 and 100
 *
 * On failure, throws an exception or returns YPwmOutput::DUTYCYCLEATPOWERON_INVALID.
 */
double YPwmOutput::get_dutyCycleAtPowerOn(void)
{
    double res = 0.0;
    yEnterCriticalSection(&_this_cs);
    try {
        if (_cacheExpiration <= YAPI::GetTickCount()) {
            if (this->_load_unsafe(YAPI::_yapiContext.GetCacheValidity()) != YAPI_SUCCESS) {
                {
                    yLeaveCriticalSection(&_this_cs);
                    return YPwmOutput::DUTYCYCLEATPOWERON_INVALID;
                }
            }
        }
        res = _dutyCycleAtPowerOn;
    } catch (std::exception &) {
        yLeaveCriticalSection(&_this_cs);
        throw;
    }
    yLeaveCriticalSection(&_this_cs);
    return res;
}

/**
 * Retrieves a PWM generator for a given identifier.
 * The identifier can be specified using several formats:
 * <ul>
 * <li>FunctionLogicalName</li>
 * <li>ModuleSerialNumber.FunctionIdentifier</li>
 * <li>ModuleSerialNumber.FunctionLogicalName</li>
 * <li>ModuleLogicalName.FunctionIdentifier</li>
 * <li>ModuleLogicalName.FunctionLogicalName</li>
 * </ul>
 *
 * This function does not require that the PWM generator is online at the time
 * it is invoked. The returned object is nevertheless valid.
 * Use the method isOnline() to test if the PWM generator is
 * indeed online at a given time. In case of ambiguity when looking for
 * a PWM generator by logical name, no error is notified: the first instance
 * found is returned. The search is performed first by hardware name,
 * then by logical name.
 *
 * If a call to this object's is_online() method returns FALSE although
 * you are certain that the matching device is plugged, make sure that you did
 * call registerHub() at application initialization time.
 *
 * @param func : a string that uniquely characterizes the PWM generator, for instance
 *         YPWMTX01.pwmOutput1.
 *
 * @return a YPwmOutput object allowing you to drive the PWM generator.
 */
YPwmOutput* YPwmOutput::FindPwmOutput(string func)
{
    YPwmOutput* obj = NULL;
    int taken = 0;
    if (YAPI::_apiInitialized) {
        yEnterCriticalSection(&YAPI::_global_cs);
        taken = 1;
    }try {
        obj = (YPwmOutput*) YFunction::_FindFromCache("PwmOutput", func);
        if (obj == NULL) {
            obj = new YPwmOutput(func);
            YFunction::_AddToCache("PwmOutput", func, obj);
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
int YPwmOutput::registerValueCallback(YPwmOutputValueCallback callback)
{
    string val;
    if (callback != NULL) {
        YFunction::_UpdateValueCallbackList(this, true);
    } else {
        YFunction::_UpdateValueCallbackList(this, false);
    }
    _valueCallbackPwmOutput = callback;
    // Immediately invoke value callback with current value
    if (callback != NULL && this->isOnline()) {
        val = _advertisedValue;
        if (!(val == "")) {
            this->_invokeValueCallback(val);
        }
    }
    return 0;
}

int YPwmOutput::_invokeValueCallback(string value)
{
    if (_valueCallbackPwmOutput != NULL) {
        _valueCallbackPwmOutput(this, value);
    } else {
        YFunction::_invokeValueCallback(value);
    }
    return 0;
}

/**
 * Performs a smooth transition of the pulse duration toward a given value.
 * Any period, frequency, duty cycle or pulse width change will cancel any ongoing transition process.
 *
 * @param ms_target   : new pulse duration at the end of the transition
 *         (floating-point number, representing the pulse duration in milliseconds)
 * @param ms_duration : total duration of the transition, in milliseconds
 *
 * @return YAPI::SUCCESS when the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::pulseDurationMove(double ms_target,int ms_duration)
{
    string newval;
    if (ms_target < 0.0) {
        ms_target = 0.0;
    }
    newval = YapiWrapper::ysprintf("%dms:%d", (int) floor(ms_target*65536+0.5),ms_duration);
    return this->set_pwmTransition(newval);
}

/**
 * Performs a smooth change of the duty cycle toward a given value.
 * Any period, frequency, duty cycle or pulse width change will cancel any ongoing transition process.
 *
 * @param target      : new duty cycle at the end of the transition
 *         (percentage, floating-point number between 0 and 100)
 * @param ms_duration : total duration of the transition, in milliseconds
 *
 * @return YAPI::SUCCESS when the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::dutyCycleMove(double target,int ms_duration)
{
    string newval;
    if (target < 0.0) {
        target = 0.0;
    }
    if (target > 100.0) {
        target = 100.0;
    }
    newval = YapiWrapper::ysprintf("%d:%d", (int) floor(target*65536+0.5),ms_duration);
    return this->set_pwmTransition(newval);
}

/**
 * Performs a smooth frequency change toward a given value.
 * Any period, frequency, duty cycle or pulse width change will cancel any ongoing transition process.
 *
 * @param target      : new frequency at the end of the transition (floating-point number)
 * @param ms_duration : total duration of the transition, in milliseconds
 *
 * @return YAPI::SUCCESS when the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::frequencyMove(double target,int ms_duration)
{
    string newval;
    if (target < 0.001) {
        target = 0.001;
    }
    newval = YapiWrapper::ysprintf("%gHz:%d", target,ms_duration);
    return this->set_pwmTransition(newval);
}

/**
 * Performs a smooth transition toward a specified value of the phase shift between this channel
 * and the other channel. The phase shift is executed by slightly changing the frequency
 * temporarily during the specified duration. This function only makes sense when both channels
 * are running, either at the same frequency, or at a multiple of the channel frequency.
 * Any period, frequency, duty cycle or pulse width change will cancel any ongoing transition process.
 *
 * @param target      : phase shift at the end of the transition, in milliseconds (floating-point number)
 * @param ms_duration : total duration of the transition, in milliseconds
 *
 * @return YAPI::SUCCESS when the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::phaseMove(double target,int ms_duration)
{
    string newval;
    newval = YapiWrapper::ysprintf("%gps:%d", target,ms_duration);
    return this->set_pwmTransition(newval);
}

/**
 * Trigger a given number of pulses of specified duration, at current frequency.
 * At the end of the pulse train, revert to the original state of the PWM generator.
 *
 * @param ms_target : desired pulse duration
 *         (floating-point number, representing the pulse duration in milliseconds)
 * @param n_pulses  : desired pulse count
 *
 * @return YAPI::SUCCESS when the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::triggerPulsesByDuration(double ms_target,int n_pulses)
{
    string newval;
    if (ms_target < 0.0) {
        ms_target = 0.0;
    }
    newval = YapiWrapper::ysprintf("%dms*%d", (int) floor(ms_target*65536+0.5),n_pulses);
    return this->set_pwmTransition(newval);
}

/**
 * Trigger a given number of pulses of specified duration, at current frequency.
 * At the end of the pulse train, revert to the original state of the PWM generator.
 *
 * @param target   : desired duty cycle for the generated pulses
 *         (percentage, floating-point number between 0 and 100)
 * @param n_pulses : desired pulse count
 *
 * @return YAPI::SUCCESS when the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::triggerPulsesByDutyCycle(double target,int n_pulses)
{
    string newval;
    if (target < 0.0) {
        target = 0.0;
    }
    if (target > 100.0) {
        target = 100.0;
    }
    newval = YapiWrapper::ysprintf("%d*%d", (int) floor(target*65536+0.5),n_pulses);
    return this->set_pwmTransition(newval);
}

/**
 * Trigger a given number of pulses at the specified frequency, using current duty cycle.
 * At the end of the pulse train, revert to the original state of the PWM generator.
 *
 * @param target   : desired frequency for the generated pulses (floating-point number)
 * @param n_pulses : desired pulse count
 *
 * @return YAPI::SUCCESS when the call succeeds.
 *
 * On failure, throws an exception or returns a negative error code.
 */
int YPwmOutput::triggerPulsesByFrequency(double target,int n_pulses)
{
    string newval;
    if (target < 0.001) {
        target = 0.001;
    }
    newval = YapiWrapper::ysprintf("%gHz*%d", target,n_pulses);
    return this->set_pwmTransition(newval);
}

int YPwmOutput::markForRepeat(void)
{
    return this->set_pwmTransition(":");
}

int YPwmOutput::repeatFromMark(void)
{
    return this->set_pwmTransition("R");
}

YPwmOutput *YPwmOutput::nextPwmOutput(void)
{
    string  hwid;

    if(YISERR(_nextFunction(hwid)) || hwid=="") {
        return NULL;
    }
    return YPwmOutput::FindPwmOutput(hwid);
}

YPwmOutput *YPwmOutput::FirstPwmOutput(void)
{
    vector<YFUN_DESCR>   v_fundescr;
    YDEV_DESCR             ydevice;
    string              serial, funcId, funcName, funcVal, errmsg;

    if(YISERR(YapiWrapper::getFunctionsByClass("PwmOutput", 0, v_fundescr, sizeof(YFUN_DESCR), errmsg)) ||
       v_fundescr.size() == 0 ||
       YISERR(YapiWrapper::getFunctionInfo(v_fundescr[0], ydevice, serial, funcId, funcName, funcVal, errmsg))) {
        return NULL;
    }
    return YPwmOutput::FindPwmOutput(serial+"."+funcId);
}

//--- (end of YPwmOutput implementation)

//--- (YPwmOutput functions)
//--- (end of YPwmOutput functions)

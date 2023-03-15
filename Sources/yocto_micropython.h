/*********************************************************************
 *
 *  $Id: yocto_micropython.h 45395 2021-05-31 07:12:50Z web $
 *
 *  Declares yFindMicroPython(), the high-level API for MicroPython functions
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


#ifndef YOCTO_MICROPYTHON_H
#define YOCTO_MICROPYTHON_H

#include <cfloat>
#include <cmath>

#include "yocto_api.h"

#ifdef YOCTOLIB_NAMESPACE
namespace YOCTOLIB_NAMESPACE
{
#endif

//--- (YMicroPython return codes)
//--- (end of YMicroPython return codes)
//--- (YMicroPython yapiwrapper)
//--- (end of YMicroPython yapiwrapper)
//--- (YMicroPython definitions)
class YMicroPython; // forward declaration

typedef void (*YMicroPythonValueCallback)(YMicroPython *func, const string& functionValue);
#define Y_COMMAND_INVALID               (YAPI_INVALID_STRING)
//--- (end of YMicroPython definitions)

//--- (YMicroPython declaration)
/**
 * YMicroPython Class: cellular interface control interface
 *
 * The YCellular class provides control over cellular network parameters
 * and status for devices that are GSM-enabled.
 * Note that TCP/IP parameters are configured separately, using class YNetwork.
 */
class YOCTO_CLASS_EXPORT YMicroPython: public YFunction {
#ifdef __BORLANDC__
#pragma option push -w-8022
#endif
//--- (end of YMicroPython declaration)
protected:
    //--- (YMicroPython attributes)
    // Attributes (function value cache)
    string          _command;
    YMicroPythonValueCallback _valueCallbackMicroPython;

    friend YMicroPython *yFindMicroPython(const string& func);
    friend YMicroPython *yFirstMicroPython(void);

    // Function-specific method for parsing of JSON output and caching result
    virtual int     _parseAttr(YJSONObject *json_val);

    // Constructor is protected, use yFindMicroPython factory function to instantiate
    YMicroPython(const string& func);
    //--- (end of YMicroPython attributes)

public:
    virtual ~YMicroPython();
    //--- (YMicroPython accessors declaration)

    static const string COMMAND_INVALID;

    string              get_command(void);

    inline string       command(void)
    { return this->get_command(); }

    int             set_command(const string& newval);
    inline int      setCommand(const string& newval)
    { return this->set_command(newval); }

    /**
     * Retrieves a cellular interface for a given identifier.
     * The identifier can be specified using several formats:
     * <ul>
     * <li>FunctionLogicalName</li>
     * <li>ModuleSerialNumber.FunctionIdentifier</li>
     * <li>ModuleSerialNumber.FunctionLogicalName</li>
     * <li>ModuleLogicalName.FunctionIdentifier</li>
     * <li>ModuleLogicalName.FunctionLogicalName</li>
     * </ul>
     *
     * This function does not require that the cellular interface is online at the time
     * it is invoked. The returned object is nevertheless valid.
     * Use the method isOnline() to test if the cellular interface is
     * indeed online at a given time. In case of ambiguity when looking for
     * a cellular interface by logical name, no error is notified: the first instance
     * found is returned. The search is performed first by hardware name,
     * then by logical name.
     *
     * If a call to this object's is_online() method returns FALSE although
     * you are certain that the matching device is plugged, make sure that you did
     * call registerHub() at application initialization time.
     *
     * @param func : a string that uniquely characterizes the cellular interface, for instance
     *         MyDevice.microPython.
     *
     * @return a YMicroPython object allowing you to drive the cellular interface.
     */
    static YMicroPython* FindMicroPython(string func);

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
    virtual int         registerValueCallback(YMicroPythonValueCallback callback);
    using YFunction::registerValueCallback;

    virtual int         _invokeValueCallback(string value);


    inline static YMicroPython *Find(string func)
    { return YMicroPython::FindMicroPython(func); }

    /**
     * Continues the enumeration of cellular interfaces started using yFirstMicroPython().
     * Caution: You can't make any assumption about the returned cellular interfaces order.
     * If you want to find a specific a cellular interface, use MicroPython.findMicroPython()
     * and a hardwareID or a logical name.
     *
     * @return a pointer to a YMicroPython object, corresponding to
     *         a cellular interface currently online, or a NULL pointer
     *         if there are no more cellular interfaces to enumerate.
     */
           YMicroPython    *nextMicroPython(void);
    inline YMicroPython    *next(void)
    { return this->nextMicroPython();}

    /**
     * Starts the enumeration of cellular interfaces currently accessible.
     * Use the method YMicroPython::nextMicroPython() to iterate on
     * next cellular interfaces.
     *
     * @return a pointer to a YMicroPython object, corresponding to
     *         the first cellular interface currently online, or a NULL pointer
     *         if there are none.
     */
           static YMicroPython *FirstMicroPython(void);
    inline static YMicroPython *First(void)
    { return YMicroPython::FirstMicroPython();}
#ifdef __BORLANDC__
#pragma option pop
#endif
    //--- (end of YMicroPython accessors declaration)
};

//--- (YMicroPython functions declaration)

/**
 * Retrieves a cellular interface for a given identifier.
 * The identifier can be specified using several formats:
 * <ul>
 * <li>FunctionLogicalName</li>
 * <li>ModuleSerialNumber.FunctionIdentifier</li>
 * <li>ModuleSerialNumber.FunctionLogicalName</li>
 * <li>ModuleLogicalName.FunctionIdentifier</li>
 * <li>ModuleLogicalName.FunctionLogicalName</li>
 * </ul>
 *
 * This function does not require that the cellular interface is online at the time
 * it is invoked. The returned object is nevertheless valid.
 * Use the method isOnline() to test if the cellular interface is
 * indeed online at a given time. In case of ambiguity when looking for
 * a cellular interface by logical name, no error is notified: the first instance
 * found is returned. The search is performed first by hardware name,
 * then by logical name.
 *
 * If a call to this object's is_online() method returns FALSE although
 * you are certain that the matching device is plugged, make sure that you did
 * call registerHub() at application initialization time.
 *
 * @param func : a string that uniquely characterizes the cellular interface, for instance
 *         MyDevice.microPython.
 *
 * @return a YMicroPython object allowing you to drive the cellular interface.
 */
inline YMicroPython *yFindMicroPython(const string& func)
{ return YMicroPython::FindMicroPython(func);}
/**
 * Starts the enumeration of cellular interfaces currently accessible.
 * Use the method YMicroPython::nextMicroPython() to iterate on
 * next cellular interfaces.
 *
 * @return a pointer to a YMicroPython object, corresponding to
 *         the first cellular interface currently online, or a NULL pointer
 *         if there are none.
 */
inline YMicroPython *yFirstMicroPython(void)
{ return YMicroPython::FirstMicroPython();}

//--- (end of YMicroPython functions declaration)

#ifdef YOCTOLIB_NAMESPACE
// end of namespace definition
}
#endif

#endif

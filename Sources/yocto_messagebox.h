/*********************************************************************
 *
 * $Id: yocto_messagebox.h 55635 2023-07-26 09:20:02Z seb $
 *
 * Declares yFindMessageBox(), the high-level API for MessageBox functions
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


#ifndef YOCTO_MESSAGEBOX_H
#define YOCTO_MESSAGEBOX_H

#include <cfloat>
#include <cmath>

#include "yocto_api.h"

#ifdef YOCTOLIB_NAMESPACE
namespace YOCTOLIB_NAMESPACE
{
#endif
//--- (generated code: YMessageBox return codes)
//--- (end of generated code: YMessageBox return codes)
//--- (generated code: YMessageBox definitions)
class YMessageBox; // forward declaration

typedef void (*YMessageBoxValueCallback)(YMessageBox *func, const string& functionValue);
#define Y_SLOTSINUSE_INVALID            (YAPI_INVALID_UINT)
#define Y_SLOTSCOUNT_INVALID            (YAPI_INVALID_UINT)
#define Y_SLOTSBITMAP_INVALID           (YAPI_INVALID_STRING)
#define Y_PDUSENT_INVALID               (YAPI_INVALID_UINT)
#define Y_PDURECEIVED_INVALID           (YAPI_INVALID_UINT)
#define Y_OBEY_INVALID                  (YAPI_INVALID_STRING)
#define Y_COMMAND_INVALID               (YAPI_INVALID_STRING)
//--- (end of generated code: YMessageBox definitions)

//--- (generated code: YSms definitions)
//--- (end of generated code: YSms definitions)


//--- (generated code: YSms declaration)
/**
 * YSms Class: SMS message sent or received, returned by messageBox.get_messages or messageBox.newMessage
 *
 * YSms objects are used to describe an SMS message, received or to be sent.
 * These objects are used in particular in conjunction with the YMessageBox class.
 */
class YOCTO_CLASS_EXPORT YSms {
#ifdef __BORLANDC__
#pragma option push -w-8022
#endif
//--- (end of generated code: YSms declaration)
    //--- (generated code: YSms attributes)
    // Attributes (function value cache)
    YMessageBox*    _mbox;
    int             _slot;
    bool            _deliv;
    string          _smsc;
    int             _mref;
    string          _orig;
    string          _dest;
    int             _pid;
    int             _alphab;
    int             _mclass;
    string          _stamp;
    string          _udh;
    string          _udata;
    int             _npdu;
    string          _pdu;
    vector<YSms>    _parts;
    string          _aggSig;
    int             _aggIdx;
    int             _aggCnt;
    //--- (end of generated code: YSms attributes)
    //--- (generated code: YSms constructor)

    //--- (end of generated code: YSms constructor)
    //--- (generated code: YSms initialization)
    //--- (end of generated code: YSms initialization)

public:
    YSms(void);
    YSms(YMessageBox *mbox);
    virtual ~YSms(){};
    //--- (generated code: YSms accessors declaration)


    virtual int         get_slot(void);

    virtual string      get_smsc(void);

    virtual int         get_msgRef(void);

    virtual string      get_sender(void);

    virtual string      get_recipient(void);

    virtual int         get_protocolId(void);

    virtual bool        isReceived(void);

    virtual int         get_alphabet(void);

    virtual int         get_msgClass(void);

    virtual int         get_dcs(void);

    virtual string      get_timestamp(void);

    virtual string      get_userDataHeader(void);

    virtual string      get_userData(void);

    /**
     * Returns the content of the message.
     *
     * @return  a string with the content of the message.
     */
    virtual string      get_textData(void);

    virtual vector<int> get_unicodeData(void);

    virtual int         get_partCount(void);

    virtual string      get_pdu(void);

    virtual vector<YSms> get_parts(void);

    virtual string      get_concatSignature(void);

    virtual int         get_concatIndex(void);

    virtual int         get_concatCount(void);

    virtual int         set_slot(int val);

    virtual int         set_received(bool val);

    virtual int         set_smsc(string val);

    virtual int         set_msgRef(int val);

    virtual int         set_sender(string val);

    virtual int         set_recipient(string val);

    virtual int         set_protocolId(int val);

    virtual int         set_alphabet(int val);

    virtual int         set_msgClass(int val);

    virtual int         set_dcs(int val);

    virtual int         set_timestamp(string val);

    virtual int         set_userDataHeader(string val);

    virtual int         set_userData(string val);

    virtual int         convertToUnicode(void);

    /**
     * Add a regular text to the SMS. This function support messages
     * of more than 160 characters. ISO-latin accented characters
     * are supported. For messages with special unicode characters such as asian
     * characters and emoticons, use the  addUnicodeData method.
     *
     * @param val : the text to be sent in the message
     *
     * @return YAPI::SUCCESS when the call succeeds.
     */
    virtual int         addText(string val);

    /**
     * Add a unicode text to the SMS. This function support messages
     * of more than 160 characters, using SMS concatenation.
     *
     * @param val : an array of special unicode characters
     *
     * @return YAPI::SUCCESS when the call succeeds.
     */
    virtual int         addUnicodeData(vector<int> val);

    virtual int         set_pdu(string pdu);

    virtual int         set_parts(vector<YSms> parts);

    virtual string      encodeAddress(string addr);

    virtual string      decodeAddress(string addr,int ofs,int siz);

    virtual string      encodeTimeStamp(string exp);

    virtual string      decodeTimeStamp(string exp,int ofs,int siz);

    virtual int         udataSize(void);

    virtual string      encodeUserData(void);

    virtual int         generateParts(void);

    virtual int         generatePdu(void);

    virtual int         parseUserDataHeader(void);

    virtual int         parsePdu(string pdu);

    /**
     * Sends the SMS to the recipient. Messages of more than 160 characters are supported
     * using SMS concatenation.
     *
     * @return YAPI::SUCCESS when the call succeeds.
     *
     * On failure, throws an exception or returns a negative error code.
     */
    virtual int         send(void);

    virtual int         deleteFromSIM(void);

#ifdef __BORLANDC__
#pragma option pop
#endif
    //--- (end of generated code: YSms accessors declaration)
};


//--- (generated code: YMessageBox declaration)
/**
 * YMessageBox Class: SMS message box interface control interface, available for instance in the
 * YoctoHub-GSM-2G, the YoctoHub-GSM-3G-EU, the YoctoHub-GSM-3G-NA or the YoctoHub-GSM-4G
 *
 * The YMessageBox class provides SMS sending and receiving capability for
 * GSM-enabled Yoctopuce devices.
 */
class YOCTO_CLASS_EXPORT YMessageBox: public YFunction {
#ifdef __BORLANDC__
#pragma option push -w-8022
#endif
//--- (end of generated code: YMessageBox declaration)
protected:
    //--- (generated code: YMessageBox attributes)
    // Attributes (function value cache)
    int             _slotsInUse;
    int             _slotsCount;
    string          _slotsBitmap;
    int             _pduSent;
    int             _pduReceived;
    string          _obey;
    string          _command;
    YMessageBoxValueCallback _valueCallbackMessageBox;
    int             _nextMsgRef;
    string          _prevBitmapStr;
    vector<YSms>    _pdus;
    vector<YSms>    _messages;
    bool            _gsm2unicodeReady;
    vector<int>     _gsm2unicode;
    string          _iso2gsm;

    friend YMessageBox *yFindMessageBox(const string& func);
    friend YMessageBox *yFirstMessageBox(void);

    // Function-specific method for parsing of JSON output and caching result
    virtual int     _parseAttr(YJSONObject *json_val);

    // Constructor is protected, use yFindMessageBox factory function to instantiate
    YMessageBox(const string& func);
    //--- (end of generated code: YMessageBox attributes)

public:
    ~YMessageBox();
    //--- (generated code: YMessageBox accessors declaration)

    static const int SLOTSINUSE_INVALID = YAPI_INVALID_UINT;
    static const int SLOTSCOUNT_INVALID = YAPI_INVALID_UINT;
    static const string SLOTSBITMAP_INVALID;
    static const int PDUSENT_INVALID = YAPI_INVALID_UINT;
    static const int PDURECEIVED_INVALID = YAPI_INVALID_UINT;
    static const string OBEY_INVALID;
    static const string COMMAND_INVALID;

    /**
     * Returns the number of message storage slots currently in use.
     *
     * @return an integer corresponding to the number of message storage slots currently in use
     *
     * On failure, throws an exception or returns YMessageBox::SLOTSINUSE_INVALID.
     */
    int                 get_slotsInUse(void);

    inline int          slotsInUse(void)
    { return this->get_slotsInUse(); }

    /**
     * Returns the total number of message storage slots on the SIM card.
     *
     * @return an integer corresponding to the total number of message storage slots on the SIM card
     *
     * On failure, throws an exception or returns YMessageBox::SLOTSCOUNT_INVALID.
     */
    int                 get_slotsCount(void);

    inline int          slotsCount(void)
    { return this->get_slotsCount(); }

    string              get_slotsBitmap(void);

    inline string       slotsBitmap(void)
    { return this->get_slotsBitmap(); }

    /**
     * Returns the number of SMS units sent so far.
     *
     * @return an integer corresponding to the number of SMS units sent so far
     *
     * On failure, throws an exception or returns YMessageBox::PDUSENT_INVALID.
     */
    int                 get_pduSent(void);

    inline int          pduSent(void)
    { return this->get_pduSent(); }

    /**
     * Changes the value of the outgoing SMS units counter.
     *
     * @param newval : an integer corresponding to the value of the outgoing SMS units counter
     *
     * @return YAPI::SUCCESS if the call succeeds.
     *
     * On failure, throws an exception or returns a negative error code.
     */
    int             set_pduSent(int newval);
    inline int      setPduSent(int newval)
    { return this->set_pduSent(newval); }

    /**
     * Returns the number of SMS units received so far.
     *
     * @return an integer corresponding to the number of SMS units received so far
     *
     * On failure, throws an exception or returns YMessageBox::PDURECEIVED_INVALID.
     */
    int                 get_pduReceived(void);

    inline int          pduReceived(void)
    { return this->get_pduReceived(); }

    /**
     * Changes the value of the incoming SMS units counter.
     *
     * @param newval : an integer corresponding to the value of the incoming SMS units counter
     *
     * @return YAPI::SUCCESS if the call succeeds.
     *
     * On failure, throws an exception or returns a negative error code.
     */
    int             set_pduReceived(int newval);
    inline int      setPduReceived(int newval)
    { return this->set_pduReceived(newval); }

    /**
     * Returns the phone number authorized to send remote management commands.
     * When a phone number is specified, the hub will take contre of all incoming
     * SMS messages: it will execute commands coming from the authorized number,
     * and delete all messages once received (whether authorized or not).
     * If you need to receive SMS messages using your own software, leave this
     * attribute empty.
     *
     * @return a string corresponding to the phone number authorized to send remote management commands
     *
     * On failure, throws an exception or returns YMessageBox::OBEY_INVALID.
     */
    string              get_obey(void);

    inline string       obey(void)
    { return this->get_obey(); }

    /**
     * Changes the phone number authorized to send remote management commands.
     * The phone number usually starts with a '+' and does not include spacers.
     * When a phone number is specified, the hub will take contre of all incoming
     * SMS messages: it will execute commands coming from the authorized number,
     * and delete all messages once received (whether authorized or not).
     * If you need to receive SMS messages using your own software, leave this
     * attribute empty. Remember to call the saveToFlash() method of the
     * module if the modification must be kept.
     *
     * This feature is only available since YoctoHub-GSM-4G.
     *
     * @param newval : a string corresponding to the phone number authorized to send remote management commands
     *
     * @return YAPI::SUCCESS if the call succeeds.
     *
     * On failure, throws an exception or returns a negative error code.
     */
    int             set_obey(const string& newval);
    inline int      setObey(const string& newval)
    { return this->set_obey(newval); }

    string              get_command(void);

    inline string       command(void)
    { return this->get_command(); }

    int             set_command(const string& newval);
    inline int      setCommand(const string& newval)
    { return this->set_command(newval); }

    /**
     * Retrieves a SMS message box interface for a given identifier.
     * The identifier can be specified using several formats:
     * <ul>
     * <li>FunctionLogicalName</li>
     * <li>ModuleSerialNumber.FunctionIdentifier</li>
     * <li>ModuleSerialNumber.FunctionLogicalName</li>
     * <li>ModuleLogicalName.FunctionIdentifier</li>
     * <li>ModuleLogicalName.FunctionLogicalName</li>
     * </ul>
     *
     * This function does not require that the SMS message box interface is online at the time
     * it is invoked. The returned object is nevertheless valid.
     * Use the method isOnline() to test if the SMS message box interface is
     * indeed online at a given time. In case of ambiguity when looking for
     * a SMS message box interface by logical name, no error is notified: the first instance
     * found is returned. The search is performed first by hardware name,
     * then by logical name.
     *
     * If a call to this object's is_online() method returns FALSE although
     * you are certain that the matching device is plugged, make sure that you did
     * call registerHub() at application initialization time.
     *
     * @param func : a string that uniquely characterizes the SMS message box interface, for instance
     *         YHUBGSM1.messageBox.
     *
     * @return a YMessageBox object allowing you to drive the SMS message box interface.
     */
    static YMessageBox* FindMessageBox(string func);

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
    virtual int         registerValueCallback(YMessageBoxValueCallback callback);
    using YFunction::registerValueCallback;

    virtual int         _invokeValueCallback(string value);

    virtual int         nextMsgRef(void);

    virtual int         clearSIMSlot(int slot);

    virtual string      _AT(string cmd);

    virtual YSms        fetchPdu(int slot);

    virtual int         initGsm2Unicode(void);

    virtual vector<int> gsm2unicode(string gsm);

    virtual string      gsm2str(string gsm);

    virtual string      str2gsm(string msg);

    virtual int         checkNewMessages(void);

    virtual vector<YSms> get_pdus(void);

    /**
     * Clear the SMS units counters.
     *
     * @return YAPI::SUCCESS when the call succeeds.
     *
     * On failure, throws an exception or returns a negative error code.
     */
    virtual int         clearPduCounters(void);

    /**
     * Sends a regular text SMS, with standard parameters. This function can send messages
     * of more than 160 characters, using SMS concatenation. ISO-latin accented characters
     * are supported. For sending messages with special unicode characters such as asian
     * characters and emoticons, use newMessage to create a new message and define
     * the content of using methods addText and addUnicodeData.
     *
     * @param recipient : a text string with the recipient phone number, either as a
     *         national number, or in international format starting with a plus sign
     * @param message : the text to be sent in the message
     *
     * @return YAPI::SUCCESS when the call succeeds.
     *
     * On failure, throws an exception or returns a negative error code.
     */
    virtual int         sendTextMessage(string recipient,string message);

    /**
     * Sends a Flash SMS (class 0 message). Flash messages are displayed on the handset
     * immediately and are usually not saved on the SIM card. This function can send messages
     * of more than 160 characters, using SMS concatenation. ISO-latin accented characters
     * are supported. For sending messages with special unicode characters such as asian
     * characters and emoticons, use newMessage to create a new message and define
     * the content of using methods addText et addUnicodeData.
     *
     * @param recipient : a text string with the recipient phone number, either as a
     *         national number, or in international format starting with a plus sign
     * @param message : the text to be sent in the message
     *
     * @return YAPI::SUCCESS when the call succeeds.
     *
     * On failure, throws an exception or returns a negative error code.
     */
    virtual int         sendFlashMessage(string recipient,string message);

    /**
     * Creates a new empty SMS message, to be configured and sent later on.
     *
     * @param recipient : a text string with the recipient phone number, either as a
     *         national number, or in international format starting with a plus sign
     *
     * @return YAPI::SUCCESS when the call succeeds.
     *
     * On failure, throws an exception or returns a negative error code.
     */
    virtual YSms        newMessage(string recipient);

    /**
     * Returns the list of messages received and not deleted. This function
     * will automatically decode concatenated SMS.
     *
     * @return an YSms object list.
     *
     * On failure, throws an exception or returns an empty list.
     */
    virtual vector<YSms> get_messages(void);


    inline static YMessageBox *Find(string func)
    { return YMessageBox::FindMessageBox(func); }

    /**
     * Continues the enumeration of SMS message box interfaces started using yFirstMessageBox().
     * Caution: You can't make any assumption about the returned SMS message box interfaces order.
     * If you want to find a specific a SMS message box interface, use MessageBox.findMessageBox()
     * and a hardwareID or a logical name.
     *
     * @return a pointer to a YMessageBox object, corresponding to
     *         a SMS message box interface currently online, or a NULL pointer
     *         if there are no more SMS message box interfaces to enumerate.
     */
           YMessageBox     *nextMessageBox(void);
    inline YMessageBox     *next(void)
    { return this->nextMessageBox();}

    /**
     * Starts the enumeration of SMS message box interfaces currently accessible.
     * Use the method YMessageBox::nextMessageBox() to iterate on
     * next SMS message box interfaces.
     *
     * @return a pointer to a YMessageBox object, corresponding to
     *         the first SMS message box interface currently online, or a NULL pointer
     *         if there are none.
     */
           static YMessageBox *FirstMessageBox(void);
    inline static YMessageBox *First(void)
    { return YMessageBox::FirstMessageBox();}
#ifdef __BORLANDC__
#pragma option pop
#endif
    //--- (end of generated code: YMessageBox accessors declaration)
};

//--- (generated code: YMessageBox functions declaration)

/**
 * Retrieves a SMS message box interface for a given identifier.
 * The identifier can be specified using several formats:
 * <ul>
 * <li>FunctionLogicalName</li>
 * <li>ModuleSerialNumber.FunctionIdentifier</li>
 * <li>ModuleSerialNumber.FunctionLogicalName</li>
 * <li>ModuleLogicalName.FunctionIdentifier</li>
 * <li>ModuleLogicalName.FunctionLogicalName</li>
 * </ul>
 *
 * This function does not require that the SMS message box interface is online at the time
 * it is invoked. The returned object is nevertheless valid.
 * Use the method isOnline() to test if the SMS message box interface is
 * indeed online at a given time. In case of ambiguity when looking for
 * a SMS message box interface by logical name, no error is notified: the first instance
 * found is returned. The search is performed first by hardware name,
 * then by logical name.
 *
 * If a call to this object's is_online() method returns FALSE although
 * you are certain that the matching device is plugged, make sure that you did
 * call registerHub() at application initialization time.
 *
 * @param func : a string that uniquely characterizes the SMS message box interface, for instance
 *         YHUBGSM1.messageBox.
 *
 * @return a YMessageBox object allowing you to drive the SMS message box interface.
 */
inline YMessageBox *yFindMessageBox(const string& func)
{ return YMessageBox::FindMessageBox(func);}
/**
 * Starts the enumeration of SMS message box interfaces currently accessible.
 * Use the method YMessageBox::nextMessageBox() to iterate on
 * next SMS message box interfaces.
 *
 * @return a pointer to a YMessageBox object, corresponding to
 *         the first SMS message box interface currently online, or a NULL pointer
 *         if there are none.
 */
inline YMessageBox *yFirstMessageBox(void)
{ return YMessageBox::FirstMessageBox();}

//--- (end of generated code: YMessageBox functions declaration)

#ifdef YOCTOLIB_NAMESPACE
}
#endif

#endif

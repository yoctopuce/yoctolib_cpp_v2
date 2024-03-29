/*********************************************************************
 *
 *  $Id: main.cpp 46880 2021-10-21 09:08:05Z seb $
 *
 *  An example that show how to use a  Yocto-GPS
 *
 *  You can find more information on our web site:
 *   Yocto-GPS documentation:
 *      https://www.yoctopuce.com/EN/products/yocto-gps/doc.html
 *   C++ V2 API Reference:
 *      https://www.yoctopuce.com/EN/doc/reference/yoctolib-cpp-EN.html
 *
 *********************************************************************/

#include "yocto_api.h"
#include "yocto_gps.h"
#include <iostream>
#include <stdlib.h>

using namespace std;

static void usage(void)
{
  cout << "usage: demo <serial_number> " << endl;
  cout << "       demo <logical_name>" << endl;
  cout << "       demo any" << endl;
  u64 now = YAPI::GetTickCount();
  while (YAPI::GetTickCount() - now < 3000) {
    // wait 3 sec to show the message
  }
  exit(1);
}

int main(int argc, const char * argv[])
{
  string errmsg, target;
  YGps *gps;

  if (argc < 2) {
    usage();
  }
  target = (string) argv[1];

  // Setup the API to use local USB devices
  if (YAPI::RegisterHub("usb", errmsg) != YAPI::SUCCESS) {
    cerr << "RegisterHub error: " << errmsg << endl;
    return 1;
  }

  if (target == "any") {
    gps = YGps::FirstGps();
    if (gps == NULL) {
      cout << "No module connected (check USB cable)" << endl;
      return 1;
    }
  } else {
    gps = YGps::FindGps(target + ".gps");
  }

  while (1) {
    if (!gps->isOnline()) {
      cout << "Module not connected (check identification and USB cable)";
      break;
    }
    if (!gps->get_isFixed()) {
      cout << "Fixing.." << endl;
    } else {
      cout << gps->get_latitude() << "  " << gps->get_longitude()    << endl;
    }
    cout << "  (press Ctrl-C to exit)" << endl;
    YAPI::Sleep(1000, errmsg);
  }
  YAPI::FreeAPI();
  return 0;
}

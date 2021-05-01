add_library (YAPI STATIC yfifo.c yhash.c ykey.c yjson.c ymemory.c ythread.c yapi.c ystream.c ytcp.c yprog.c ypkt_win.c ypkt_lin.c ypkt_osx.c yssl.c)

target_include_directories (YAPI PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
target_link_libraries (YAPI LINK_PUBLIC pthread usb-1.0)
endif()

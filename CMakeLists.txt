# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
set(PROJECT_VER "unified-1.0.1")
project(esp32-wifi-penetration-tool)

if(NOT IDF_TARGET STREQUAL "esp32")
    message(FATAL_ERROR "This fork targets ESP32-WROOM-32 / DevKit V1. Other chips are unvalidated.")
endif()
if(NOT IDF_VERSION_MAJOR EQUAL 5 OR NOT IDF_VERSION_MINOR EQUAL 5 OR NOT IDF_VERSION_PATCH EQUAL 5)
    message(FATAL_ERROR "Use the pinned ESP-IDF v5.5.5 SDK for this build.")
endif()

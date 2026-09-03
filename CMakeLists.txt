cmake_minimum_required(VERSION 3.28...3.30)

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/common/bootstrap.cmake" NO_POLICY_SCOPE)

project(${_name} VERSION ${_version} LANGUAGES CXX)

option(ENABLE_FRONTEND_API "Use obs-frontend-api for UI functionality" ON)
option(ENABLE_QT "Use Qt functionality" ON)

include(compilerconfig)
include(defaults)
include(helpers)

add_library(${CMAKE_PROJECT_NAME} MODULE)

find_package(libobs REQUIRED)
find_package(obs-frontend-api REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Core Network Widgets)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
  OBS::libobs
  OBS::obs-frontend-api
  Qt6::Core
  Qt6::Network
  Qt6::Widgets
)

target_sources(${CMAKE_PROJECT_NAME} PRIVATE src/discord_striming.cpp)

if(APPLE)
  enable_language(OBJCXX)
  find_library(SECURITY_FRAMEWORK Security REQUIRED)
  find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
  target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${SECURITY_FRAMEWORK} ${FOUNDATION_FRAMEWORK})
  target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -Wno-deprecated-declarations)
  set_source_files_properties(src/discord_striming.cpp PROPERTIES LANGUAGE OBJCXX)
elseif(WIN32)
  target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE Advapi32)
endif()

set_target_properties_plugin(${CMAKE_PROJECT_NAME} PROPERTIES OUTPUT_NAME ${_name})

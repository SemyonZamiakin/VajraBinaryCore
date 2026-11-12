cmake_minimum_required(VERSION 3.16)
project(VajraBinaryCore VERSION 0.1.0 LANGUAGES C CXX ASM)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
  message(FATAL_ERROR "Vajra Binary Core supports Linux on x86-64 only "
                      "(this is ${CMAKE_SYSTEM_NAME} / ${CMAKE_SYSTEM_PROCESSOR}).")
endif()

option(VAJRA_WERROR "Treat warnings as errors" OFF)
option(VAJRA_BUILD_TESTS "Build the test suite" ON)
option(VAJRA_BUILD_DEMO "Build the live-patching demo" ON)
set(VAJRA_SANITIZE "" CACHE STRING "Sanitizers: empty, 'address,undefined' or 'thread'")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Threads REQUIRED)

add_library(vajra_warnings INTERFACE)
target_compile_options(vajra_warnings INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor)
if(VAJRA_WERROR)
  target_compile_options(vajra_warnings INTERFACE -Werror)
endif()

if(VAJRA_SANITIZE)
  add_compile_options(-fsanitize=${VAJRA_SANITIZE} -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=${VAJRA_SANITIZE})
endif()

# ---------------------------------------------------------------- library
add_library(vajra SHARED
  src/agent.cpp
  src/migrate.cpp
  src/patch.cpp
  src/relocate.cpp
  src/safepoint.cpp
  src/status.cpp
  src/stop.cpp
  src/sys.cpp
  src/types.cpp
  src/x86.cpp)
add_library(Vajra::vajra ALIAS vajra)
target_include_directories(vajra PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_definitions(vajra PRIVATE VAJRA_VERSION_STRING="${PROJECT_VERSION}")
target_link_libraries(vajra PUBLIC Threads::Threads ${CMAKE_DL_LIBS} PRIVATE vajra_warnings)
set_target_properties(vajra PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

add_executable(vajractl tools/vajractl.cpp)
target_link_libraries(vajractl PRIVATE vajra_warnings)

# ---------------------------------------------------------------- tests / demo
if(VAJRA_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
if(VAJRA_BUILD_DEMO)
  add_subdirectory(demo)
endif()

# ---------------------------------------------------------------- install
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
install(TARGETS vajra EXPORT VajraTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS vajractl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/vajra DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT VajraTargets NAMESPACE Vajra:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Vajra)
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/VajraConfig.cmake
  "include(CMakeFindDependencyMacro)\nfind_dependency(Threads)\ninclude(\${CMAKE_CURRENT_LIST_DIR}/VajraTargets.cmake)\n")
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/VajraConfigVersion.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/VajraConfig.cmake ${CMAKE_CURRENT_BINARY_DIR}/VajraConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Vajra)

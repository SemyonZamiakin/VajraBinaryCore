cmake_minimum_required(VERSION 3.16)
project(VajraBinaryCore VERSION 0.1.0 LANGUAGES C CXX ASM)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(VAJRA_PLATFORM linux)
elseif(WIN32)
  set(VAJRA_PLATFORM windows)
else()
  set(VAJRA_PLATFORM unsupported)
endif()
if(VAJRA_PLATFORM STREQUAL "unsupported"
   OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$"
   OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Vajra Binary Core supports x86-64 Linux and x86-64 Windows only "
                      "(this is ${CMAKE_SYSTEM_NAME} / ${CMAKE_SYSTEM_PROCESSOR}).")
endif()
if(MSVC)
  message(FATAL_ERROR "Vajra uses GNU inline assembly and attributes: build with GCC or Clang "
                      "(on Windows: MinGW-w64, e.g. MSYS2 MINGW64 or CLANG64).")
endif()

option(VAJRA_WERROR "Treat warnings as errors" OFF)
option(VAJRA_BUILD_TESTS "Build the test suite" ON)
option(VAJRA_BUILD_DEMO "Build the live-patching demo" ON)
set(VAJRA_SANITIZE "" CACHE STRING "Sanitizers (Linux): empty, 'address,undefined' or 'thread'")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(WIN32)
  # Executables and DLLs side by side, so tests and the demo find vajra.dll.
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

find_package(Threads REQUIRED)

add_library(vajra_warnings INTERFACE)
target_compile_options(vajra_warnings INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor)
if(VAJRA_WERROR)
  target_compile_options(vajra_warnings INTERFACE -Werror)
endif()

if(VAJRA_SANITIZE)
  if(WIN32)
    message(FATAL_ERROR "VAJRA_SANITIZE is supported on Linux only")
  endif()
  add_compile_options(-fsanitize=${VAJRA_SANITIZE} -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=${VAJRA_SANITIZE})
endif()

# ---------------------------------------------------------------- library
set(VAJRA_SOURCES
  src/agent.cpp
  src/migrate.cpp
  src/patch.cpp
  src/relocate.cpp
  src/safepoint.cpp
  src/status.cpp
  src/sys_common.cpp
  src/types.cpp
  src/x86.cpp)
if(VAJRA_PLATFORM STREQUAL "linux")
  list(APPEND VAJRA_SOURCES src/sys_linux.cpp src/stop_linux.cpp)
else()
  list(APPEND VAJRA_SOURCES src/sys_windows.cpp src/stop_windows.cpp)
endif()

add_library(vajra SHARED ${VAJRA_SOURCES})
add_library(Vajra::vajra ALIAS vajra)
target_include_directories(vajra PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_definitions(vajra PRIVATE VAJRA_VERSION_STRING="${PROJECT_VERSION}")
target_link_libraries(vajra PUBLIC Threads::Threads PRIVATE vajra_warnings)
if(VAJRA_PLATFORM STREQUAL "linux")
  target_link_libraries(vajra PUBLIC ${CMAKE_DL_LIBS})
else()
  target_compile_definitions(vajra PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
  target_link_libraries(vajra PRIVATE advapi32)
  set_target_properties(vajra PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()
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
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
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

add_executable(arena arena.cpp)
target_link_libraries(arena PRIVATE vajra vajra_warnings)
set_target_properties(arena PROPERTIES ENABLE_EXPORTS ON)  # patch modules find host functions by name

add_library(arena_patch_v2 MODULE patch_v2.cpp)
target_link_libraries(arena_patch_v2 PRIVATE vajra vajra_warnings)

if(VAJRA_BUILD_TESTS AND NOT VAJRA_SANITIZE MATCHES "thread")
  find_program(VAJRA_BASH bash)
  if(VAJRA_BASH)
    add_test(NAME demo_live_patch
             COMMAND ${VAJRA_BASH} ${CMAKE_CURRENT_SOURCE_DIR}/run_demo.sh $<TARGET_FILE:arena>
                     $<TARGET_FILE:vajractl> $<TARGET_FILE:arena_patch_v2>)
    set_tests_properties(demo_live_patch PROPERTIES TIMEOUT 120)
    if(WIN32 AND CMAKE_VERSION VERSION_GREATER_EQUAL 3.22)
      get_filename_component(_bin ${CMAKE_CXX_COMPILER} DIRECTORY)
      set_tests_properties(demo_live_patch PROPERTIES ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_bin}")
    endif()
  endif()
endif()

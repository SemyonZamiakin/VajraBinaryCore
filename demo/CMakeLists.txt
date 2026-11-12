add_executable(arena arena.cpp)
target_link_libraries(arena PRIVATE vajra vajra_warnings)
set_target_properties(arena PROPERTIES ENABLE_EXPORTS ON)  # patch modules resolve host functions

add_library(arena_patch_v2 MODULE patch_v2.cpp)
target_link_libraries(arena_patch_v2 PRIVATE vajra vajra_warnings)

if(VAJRA_BUILD_TESTS)
  add_test(NAME demo_live_patch
           COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run_demo.sh $<TARGET_FILE:arena> $<TARGET_FILE:vajractl>
                   $<TARGET_FILE:arena_patch_v2>)
  set_tests_properties(demo_live_patch PROPERTIES TIMEOUT 120)
endif()

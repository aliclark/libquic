include_directories(../../include)

if (${ARCH} STREQUAL "arm")
  set(
    POLY1305_ARCH_SOURCES

    poly1305_arm_asm.S
  )
endif()

add_library(
  poly1305

  OBJECT

  poly1305.c
  poly1305_arm.c
  poly1305_vec.c

  ${POLY1305_ARCH_SOURCES}
)

add_executable(
  poly1305_test

  poly1305_test.cc
  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(poly1305_test bsslcrypto)
add_dependencies(all_tests poly1305_test)

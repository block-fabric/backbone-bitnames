# BitNames (eCash slot 2) rule module and binaries.
add_library(bitnames_core STATIC
  src/types.cpp
  src/chain.cpp
  src/state.cpp
  src/fixture.cpp)
target_include_directories(bitnames_core PUBLIC include)
target_link_libraries(bitnames_core PUBLIC bt_core)

if(BT_WITH_NET)
  add_executable(bitnames-fetch-blocks tools/fetch_blocks.cpp)
  target_link_libraries(bitnames-fetch-blocks PRIVATE bitnames_core bt_net)
endif()

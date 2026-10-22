# BitNames (eCash slot 2) rule module and binaries.
add_library(bitnames_core STATIC
  src/types.cpp
  src/chain.cpp
  src/state.cpp
  src/json.cpp
  src/fixture.cpp
  src/side_tips.cpp)
target_include_directories(bitnames_core PUBLIC include)
target_link_libraries(bitnames_core PUBLIC bt_core)

if(BT_WITH_NET)
  add_library(bitnames_node STATIC src/node.cpp src/wallet.cpp src/app.cpp src/appui.cpp)
  target_link_libraries(bitnames_node PUBLIC bitnames_core bt_net bt_appui)
  add_executable(bitnames src/main.cpp)
  target_link_libraries(bitnames PRIVATE bitnames_node)
  add_executable(bitnames-cli src/cli.cpp)
  target_link_libraries(bitnames-cli PRIVATE bitnames_core)
  # Fetch full blocks from a public betanet peer over their QUIC protocol (client only).
  add_executable(bitnames-fetch-blocks tools/fetch_blocks.cpp)
  target_link_libraries(bitnames-fetch-blocks PRIVATE bitnames_core bt_net)
endif()

cmake_minimum_required(VERSION 3.24)

cmake_policy(SET CMP0091 NEW)
project(AltbaseNativeCore VERSION 0.1.5 LANGUAGES CXX)

if (MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include(FetchContent)
include(CTest)

if (APPLE)
  set(ZANO_MACOS_FRAMEWORK_PLATFORM "macos-arm64_x86_64" CACHE STRING "Zano macOS xcframework platform slice")
  set(ZANO_MACOS_INSTALL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/_install_macosx")
  set(ZANO_MACOS_BOOST_ROOT "${ZANO_MACOS_INSTALL_ROOT}/libboost.xcframework/${ZANO_MACOS_FRAMEWORK_PLATFORM}")
  set(ZANO_MACOS_OPENSSL_ROOT "${ZANO_MACOS_INSTALL_ROOT}/libopenssl.xcframework/${ZANO_MACOS_FRAMEWORK_PLATFORM}")
  set(ZANO_MACOS_ICONV_ROOT "${ZANO_MACOS_INSTALL_ROOT}/libiconv.xcframework/${ZANO_MACOS_FRAMEWORK_PLATFORM}")
  set(ZANO_MACOS_PLAIN_WALLET_LIB "${ZANO_MACOS_INSTALL_ROOT}/libzano-plain-wallet.xcframework/${ZANO_MACOS_FRAMEWORK_PLATFORM}/libzano-plain-wallet.a")
elseif (NOT WIN32)
  find_package(OpenSSL REQUIRED)
  find_package(CURL REQUIRED)
endif()

set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_ECMULT_WINDOW_SIZE 8 CACHE STRING "" FORCE)
set(SECP256K1_ECMULT_GEN_KB 2 CACHE STRING "" FORCE)
set(SECP256K1_ENABLE_MODULE_ECDH OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS ON)
FetchContent_Declare(
  secp256k1
  GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
  GIT_TAG v0.7.1
)
FetchContent_MakeAvailable(secp256k1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

function(altbase_add_module_version target filename internal_name description)
  set(MODULE_FILENAME "${filename}")
  set(MODULE_INTERNAL_NAME "${internal_name}")
  set(MODULE_DESCRIPTION "${description}")
  set(resource_dir "${CMAKE_CURRENT_BINARY_DIR}/version-resources")
  file(MAKE_DIRECTORY "${resource_dir}")
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/native_module_version.rc.in"
    "${resource_dir}/${target}.rc"
    @ONLY
  )
  target_sources(${target} PRIVATE "${resource_dir}/${target}.rc")
endfunction()

if (WIN32)
  altbase_add_module_version(secp256k1 "libsecp256k1-6.dll" "AltbaseSecp256k1" "Altbase secp256k1 Cryptography Module")
endif()

add_library(altbase_utxo_address SHARED
  src/address_validation.cpp src/protocol.cpp src/utxo_keys.cpp src/utxo_keys_module.cpp
)
add_library(altbase_utxo_derivation SHARED
  src/protocol.cpp src/wallet_derivation.cpp src/utxo_keys.cpp src/utxo_keys_module.cpp
)
add_library(altbase_utxo_signer SHARED
  src/protocol.cpp src/tx_signing.cpp src/wallet_derivation.cpp src/utxo_tx.cpp src/utxo_tx_module.cpp
)
add_library(altbase_utxo_planner SHARED
  src/protocol.cpp src/tx_planning.cpp src/utxo_tx.cpp src/utxo_tx_module.cpp
)
add_library(altbase_wallet_vault SHARED
  src/protocol.cpp
  src/wallet_secret.cpp
  src/wallet_vault.cpp
  src/wallet_vault_module.cpp
)
set(ALTBASE_UTXO_SERVICE_TARGETS
  altbase_utxo_address altbase_utxo_derivation altbase_utxo_signer altbase_utxo_planner
)
set(ALTBASE_LOCAL_CORE_TARGETS ${ALTBASE_UTXO_SERVICE_TARGETS} altbase_wallet_vault)
set_target_properties(${ALTBASE_LOCAL_CORE_TARGETS} PROPERTIES INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)

foreach(core_target IN LISTS ALTBASE_LOCAL_CORE_TARGETS)
  target_include_directories(${core_target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_definitions(${core_target} PRIVATE
    ALTBASE_CORE_VERSION=\"${PROJECT_VERSION}\"
    ALTBASE_RELEASE_BINARY=1
    MOBILE_WALLET_BUILD=1
  )
endforeach()
target_link_libraries(altbase_utxo_derivation PRIVATE secp256k1)
target_link_libraries(altbase_utxo_signer PRIVATE secp256k1)
target_compile_definitions(altbase_utxo_address PRIVATE
  ALTBASE_UTXO_ADDRESS_SERVICE=1
  ALTBASE_UTXO_SERVICE_REQUEST=altbase_utxo_address_request
  ALTBASE_UTXO_SERVICE_FREE=altbase_utxo_address_free
)
target_compile_definitions(altbase_utxo_derivation PRIVATE
  ALTBASE_UTXO_DERIVATION_SERVICE=1
  ALTBASE_UTXO_SERVICE_REQUEST=altbase_utxo_derivation_request
  ALTBASE_UTXO_SERVICE_FREE=altbase_utxo_derivation_free
)
target_compile_definitions(altbase_utxo_signer PRIVATE
  ALTBASE_UTXO_SIGNER_SERVICE=1
  ALTBASE_UTXO_SERVICE_REQUEST=altbase_utxo_signer_request
  ALTBASE_UTXO_SERVICE_FREE=altbase_utxo_signer_free
)
target_compile_definitions(altbase_utxo_planner PRIVATE
  ALTBASE_UTXO_PLANNER_SERVICE=1
  ALTBASE_UTXO_SERVICE_REQUEST=altbase_utxo_planner_request
  ALTBASE_UTXO_SERVICE_FREE=altbase_utxo_planner_free
)
target_compile_definitions(altbase_wallet_vault PRIVATE ALTBASE_WALLET_VAULT_EXPORTS)

add_library(altbase_net_core SHARED
  src/native_http_module.cpp
)
target_compile_definitions(altbase_net_core PRIVATE
  ALTBASE_NET_CORE_EXPORTS
  ALTBASE_RELEASE_BINARY=1
  NOMINMAX
)
target_include_directories(altbase_net_core PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)
if (WIN32)
  altbase_add_module_version(altbase_net_core "altbase_net_core.dll" "AltbaseNetworkCore" "Altbase Wallet Network Transport")
endif()

set(ALTBASE_UTXO_WALLET_MODULES)

function(altbase_add_utxo_wallet_module coin internal_name)
  set(target "altbase_${coin}_wallet")
  set(request_symbol "altbase_${coin}_wallet_request")
  set(free_symbol "altbase_${coin}_wallet_free")

  add_library(${target} SHARED
    src/utxo_wallet_module.cpp
    src/protocol.cpp
  )
  target_include_directories(${target} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(${target} PRIVATE
    ALTBASE_UTXO_MODULE_COIN="${coin}"
    ALTBASE_UTXO_MODULE_REQUEST=${request_symbol}
    ALTBASE_UTXO_MODULE_FREE=${free_symbol}
    ALTBASE_RELEASE_BINARY=1
    MOBILE_WALLET_BUILD=1
  )
  target_link_libraries(${target} PRIVATE ${ALTBASE_UTXO_SERVICE_TARGETS})
  set_target_properties(${target} PROPERTIES
    PREFIX ""
    OUTPUT_NAME "altbase_${coin}_wallet"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  )
  if (APPLE)
    set_target_properties(${target} PROPERTIES BUILD_RPATH "@loader_path" INSTALL_RPATH "@loader_path")
  elseif(UNIX)
    set_target_properties(${target} PROPERTIES BUILD_RPATH "$ORIGIN" INSTALL_RPATH "$ORIGIN")
  endif()
  if (WIN32)
    altbase_add_module_version(
      ${target}
      "altbase_${coin}_wallet.dll"
      "${internal_name}Wallet"
      "Altbase ${internal_name} Wallet Module"
    )
  endif()

  set(ALTBASE_UTXO_WALLET_MODULES ${ALTBASE_UTXO_WALLET_MODULES} ${target} PARENT_SCOPE)
endfunction()

altbase_add_utxo_wallet_module(bitcoin Bitcoin)
altbase_add_utxo_wallet_module(bitcoin2 Bitcoin2)
altbase_add_utxo_wallet_module(bitcoincashii BitcoinCashII)
altbase_add_utxo_wallet_module(firo Firo)
altbase_add_utxo_wallet_module(btgs BitcoinGoldStake)
altbase_add_utxo_wallet_module(capstash CapStash)
altbase_add_utxo_wallet_module(hypercoin HyperCoin)
altbase_add_utxo_wallet_module(mydogecoin MyDogeCoin)
altbase_add_utxo_wallet_module(pepecoin PepeCoin)
altbase_add_utxo_wallet_module(kerrigan Kerrigan)
altbase_add_utxo_wallet_module(scash SCash)
altbase_add_utxo_wallet_module(litecoinii LitecoinII)
altbase_add_utxo_wallet_module(neoxa Neoxa)
altbase_add_utxo_wallet_module(terracoin TerraCoin)
altbase_add_utxo_wallet_module(junkcoin JunkCoin)
altbase_add_utxo_wallet_module(raptoreum Raptoreum)
altbase_add_utxo_wallet_module(pearl Pearl)

set(ALTBASE_COIN_NODE_MODULES)

function(altbase_add_coin_node_module coin internal_name)
  set(target "altbase_${coin}_node")
  add_library(${target} SHARED
    src/coin_node_module.cpp
    src/native_http.cpp
    src/protocol.cpp
  )
  target_include_directories(${target} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(${target} PRIVATE
    ALTBASE_NODE_MODULE_COIN="${coin}"
    ALTBASE_NODE_MODULE_REQUEST=altbase_${coin}_node_request
    ALTBASE_NODE_MODULE_FREE=altbase_${coin}_node_free
    ALTBASE_RELEASE_BINARY=1
  )
  target_link_libraries(${target} PRIVATE altbase_net_core)
  set_target_properties(${target} PROPERTIES
    PREFIX ""
    OUTPUT_NAME "altbase_${coin}_node"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  )
  if (APPLE)
    set_target_properties(${target} PROPERTIES BUILD_RPATH "@loader_path" INSTALL_RPATH "@loader_path")
  elseif(UNIX)
    set_target_properties(${target} PROPERTIES BUILD_RPATH "$ORIGIN" INSTALL_RPATH "$ORIGIN")
  endif()
  if (WIN32)
    altbase_add_module_version(
      ${target}
      "altbase_${coin}_node.dll"
      "${internal_name}Node"
      "Altbase ${internal_name} Node Module"
    )
  endif()
  set(ALTBASE_COIN_NODE_MODULES ${ALTBASE_COIN_NODE_MODULES} ${target} PARENT_SCOPE)
endfunction()

altbase_add_coin_node_module(bitcoin Bitcoin)
altbase_add_coin_node_module(bitcoin2 Bitcoin2)
altbase_add_coin_node_module(bitcoincashii BitcoinCashII)
altbase_add_coin_node_module(firo Firo)
altbase_add_coin_node_module(btgs BitcoinGoldStake)
altbase_add_coin_node_module(capstash CapStash)
altbase_add_coin_node_module(hypercoin HyperCoin)
altbase_add_coin_node_module(mydogecoin MyDogeCoin)
altbase_add_coin_node_module(pepecoin PepeCoin)
altbase_add_coin_node_module(kerrigan Kerrigan)
altbase_add_coin_node_module(scash SCash)
altbase_add_coin_node_module(litecoinii LitecoinII)
altbase_add_coin_node_module(neoxa Neoxa)
altbase_add_coin_node_module(terracoin TerraCoin)
altbase_add_coin_node_module(junkcoin JunkCoin)
altbase_add_coin_node_module(raptoreum Raptoreum)
altbase_add_coin_node_module(pearl Pearl)
altbase_add_coin_node_module(zano Zano)
altbase_add_coin_node_module(epic Epic)
altbase_add_coin_node_module(quai Quai)
altbase_add_coin_node_module(qubic Qubic)
altbase_add_coin_node_module(kaspa Kaspa)
altbase_add_coin_node_module(ckb NervosCKB)

set(ALTBASE_CORE_BRIDGE_SOURCES
  src/main.cpp
  src/protocol.cpp
)

if (WIN32)
  list(APPEND ALTBASE_CORE_BRIDGE_SOURCES src/bridge_version.rc)
endif()

add_executable(altbase_core_bridge ${ALTBASE_CORE_BRIDGE_SOURCES})

target_link_libraries(altbase_core_bridge PRIVATE
  ${ALTBASE_UTXO_SERVICE_TARGETS}
  altbase_wallet_vault
  ${ALTBASE_UTXO_WALLET_MODULES}
  ${ALTBASE_COIN_NODE_MODULES}
)
if (WIN32)
  target_link_libraries(altbase_utxo_address PRIVATE bcrypt)
  target_link_libraries(altbase_utxo_derivation PRIVATE bcrypt)
  target_link_libraries(altbase_utxo_signer PRIVATE bcrypt)
  target_link_libraries(altbase_wallet_vault PRIVATE bcrypt)
  target_link_libraries(altbase_net_core PRIVATE winhttp)
elseif(APPLE)
  target_include_directories(${ALTBASE_LOCAL_CORE_TARGETS} PRIVATE "${ZANO_MACOS_OPENSSL_ROOT}/Headers")
  target_link_libraries(altbase_utxo_address PRIVATE "${ZANO_MACOS_OPENSSL_ROOT}/libopenssl.a")
  target_link_libraries(altbase_utxo_derivation PRIVATE "${ZANO_MACOS_OPENSSL_ROOT}/libopenssl.a")
  target_link_libraries(altbase_utxo_signer PRIVATE "${ZANO_MACOS_OPENSSL_ROOT}/libopenssl.a")
  target_link_libraries(altbase_wallet_vault PRIVATE "${ZANO_MACOS_OPENSSL_ROOT}/libopenssl.a")
  target_link_libraries(altbase_net_core PRIVATE "-lcurl")
else()
  target_link_libraries(altbase_utxo_address PRIVATE OpenSSL::Crypto)
  target_link_libraries(altbase_utxo_derivation PRIVATE OpenSSL::Crypto)
  target_link_libraries(altbase_utxo_signer PRIVATE OpenSSL::Crypto)
  target_link_libraries(altbase_wallet_vault PRIVATE OpenSSL::Crypto)
  target_link_libraries(altbase_net_core PRIVATE CURL::libcurl)
endif()
target_compile_definitions(altbase_core_bridge PRIVATE
  ALTBASE_CORE_VERSION=\"${PROJECT_VERSION}\"
  ALTBASE_RELEASE_BINARY=1
)

set(ZANO_NATIVE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib")
set(ZANO_SOURCE_ROOT "${ZANO_NATIVE_ROOT}/Zano")
set(ZANO_BUILD_ROOT "${ZANO_SOURCE_ROOT}/build/altbase-vs2022-x64")
set(ZANO_RELEASE_SRC "${ZANO_BUILD_ROOT}/src/Release")
set(ZANO_RELEASE_CONTRIB "${ZANO_BUILD_ROOT}/contrib")
set(ZANO_LINUX_BUILD_ROOT "${ZANO_SOURCE_ROOT}/build/altbase-linux-x64")
set(ZANO_LINUX_SRC "${ZANO_LINUX_BUILD_ROOT}/src")
set(ZANO_LINUX_CONTRIB "${ZANO_LINUX_BUILD_ROOT}/contrib")

if (WIN32 AND EXISTS "${ZANO_RELEASE_SRC}/currency_core.lib")
  set(ZANO_WINDOWS_DEFINES
    STATICLIB
    DISABLE_PFR_SERIALIZATION_SELFCHECK
    DISABLE_TOR
    USE_OPEN_SSL_FOR_ECDSA
    NOMINMAX
  )
  set(ZANO_WINDOWS_INCLUDE_DIRS
    "${ZANO_SOURCE_ROOT}/src"
    "${ZANO_SOURCE_ROOT}/contrib"
    "${ZANO_SOURCE_ROOT}/contrib/eos_portable_archive"
    "${ZANO_SOURCE_ROOT}/contrib/epee/include"
    "${ZANO_SOURCE_ROOT}/contrib/jwt-cpp/include"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/include"
    "${ZANO_NATIVE_ROOT}/_install_windows/openssl/x86_64/include"
    "${ZANO_BUILD_ROOT}/version"
    "${ZANO_BUILD_ROOT}/contrib/zlib"
  )
  set(ZANO_WINDOWS_LINK_DIRS
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/openssl/x86_64/lib"
  )
  set(ZANO_WINDOWS_BRIDGE_LIBS
    "${ZANO_RELEASE_SRC}/currency_core.lib"
    "${ZANO_RELEASE_SRC}/crypto.lib"
    "${ZANO_RELEASE_SRC}/common.lib"
    "${ZANO_RELEASE_CONTRIB}/db/liblmdb/Release/lmdb.lib"
    "${ZANO_RELEASE_CONTRIB}/db/libmdbx/Release/mdbx.lib"
    "${ZANO_RELEASE_CONTRIB}/zlib/Release/zlibstatic.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/openssl/x86_64/lib/libcrypto.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_system-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_filesystem-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_thread-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_timer-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_date_time-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_chrono-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_regex-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_serialization-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_atomic-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_program_options-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_locale-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_log-vc143-mt-s-x64-1_84.lib"
    "${ZANO_NATIVE_ROOT}/_install_windows/boost/x86_64/lib/libboost_log_setup-vc143-mt-s-x64-1_84.lib"
    bcrypt
    crypt32
    ntdll
    ws2_32
    mswsock
    iphlpapi
  )
  set(ZANO_WINDOWS_MODULE_LIBS
    "${ZANO_RELEASE_SRC}/wallet.lib"
    ${ZANO_WINDOWS_BRIDGE_LIBS}
    "${ZANO_NATIVE_ROOT}/_install_windows/openssl/x86_64/lib/libssl.lib"
  )
  set(EPIC_WINDOWS_STATE_IMPORT_LIB "${CMAKE_CURRENT_SOURCE_DIR}/../epic_core/target/release/altbase_epic_state.dll.lib")
  set(EPIC_WINDOWS_SENDER_IMPORT_LIB "${CMAKE_CURRENT_SOURCE_DIR}/../epic_core/target/release/altbase_epic_sender.dll.lib")

  add_library(altbase_zano_core SHARED
    src/zano_core_module.cpp
  )
  target_compile_definitions(altbase_zano_core PRIVATE
    ${ZANO_WINDOWS_DEFINES}
    ALTBASE_ZANO_CORE_EXPORTS
    ALTBASE_RELEASE_BINARY=1
    MOBILE_WALLET_BUILD=1
  )
  target_include_directories(altbase_zano_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${ZANO_WINDOWS_INCLUDE_DIRS}
  )
  target_link_directories(altbase_zano_core PRIVATE ${ZANO_WINDOWS_LINK_DIRS})
  target_link_libraries(altbase_zano_core PRIVATE ${ZANO_WINDOWS_MODULE_LIBS})

  altbase_add_module_version(altbase_utxo_address "altbase_utxo_address.dll" "AltbaseUtxoAddress" "Altbase UTXO Address Core")
  altbase_add_module_version(altbase_utxo_derivation "altbase_utxo_derivation.dll" "AltbaseUtxoDerivation" "Altbase UTXO Derivation Core")
  altbase_add_module_version(altbase_utxo_signer "altbase_utxo_signer.dll" "AltbaseUtxoSigner" "Altbase UTXO Signing Core")
  altbase_add_module_version(altbase_utxo_planner "altbase_utxo_planner.dll" "AltbaseUtxoPlanner" "Altbase UTXO Planning Core")
  altbase_add_module_version(altbase_wallet_vault "altbase_wallet_vault.dll" "AltbaseWalletVault" "Altbase Wallet Vault")
  altbase_add_module_version(altbase_zano_core "altbase_zano_core.dll" "AltbaseZanoCore" "Altbase Zano Protocol Core")
elseif(UNIX AND NOT APPLE AND EXISTS "${ZANO_LINUX_SRC}/libcurrency_core.a")
  find_package(Threads REQUIRED)
  find_package(Boost 1.74 REQUIRED COMPONENTS
    system
    filesystem
    locale
    thread
    timer
    date_time
    chrono
    regex
    serialization
    atomic
    program_options
    log
  )
  add_library(altbase_zano_core SHARED src/zano_core_module.cpp)
  target_compile_definitions(altbase_zano_core PRIVATE
    STATICLIB
    DISABLE_TOR
    DISABLE_PFR_SERIALIZATION_SELFCHECK
    USE_OPEN_SSL_FOR_ECDSA
    ALTBASE_ZANO_CORE_EXPORTS
    ALTBASE_RELEASE_BINARY=1
    MOBILE_WALLET_BUILD=1
  )
  target_include_directories(altbase_zano_core PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${ZANO_SOURCE_ROOT}/src"
    "${ZANO_SOURCE_ROOT}/contrib"
    "${ZANO_SOURCE_ROOT}/contrib/eos_portable_archive"
    "${ZANO_SOURCE_ROOT}/contrib/epee/include"
    "${ZANO_SOURCE_ROOT}/contrib/jwt-cpp/include"
    "${ZANO_LINUX_BUILD_ROOT}/version"
    "${ZANO_LINUX_BUILD_ROOT}/contrib/zlib"
  )
  target_link_libraries(altbase_zano_core PRIVATE
    "${ZANO_LINUX_SRC}/libwallet.a"
    "${ZANO_LINUX_SRC}/librpc.a"
    "${ZANO_LINUX_SRC}/libcurrency_core.a"
    "${ZANO_LINUX_SRC}/libcrypto.a"
    "${ZANO_LINUX_SRC}/libcommon.a"
    "${ZANO_LINUX_CONTRIB}/db/liblmdb/liblmdb.a"
    "${ZANO_LINUX_CONTRIB}/db/libmdbx/libmdbx.a"
    "${ZANO_LINUX_CONTRIB}/zlib/libz.a"
    "${ZANO_LINUX_CONTRIB}/miniupnp/miniupnpc/libminiupnpc.a"
    Threads::Threads
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
  )
elseif(APPLE AND EXISTS "${ZANO_MACOS_PLAIN_WALLET_LIB}")
  find_package(Threads REQUIRED)
  set(ZANO_MACOS_VERSION_DIR "${CMAKE_BINARY_DIR}/zano-version")
  file(MAKE_DIRECTORY "${ZANO_MACOS_VERSION_DIR}")
  set(VERSION "altbase-macos")
  configure_file("${ZANO_SOURCE_ROOT}/src/version.h.in" "${ZANO_MACOS_VERSION_DIR}/version.h" @ONLY)
  add_library(altbase_zano_core SHARED src/zano_core_module.cpp)
  target_compile_definitions(altbase_zano_core PRIVATE
    STATICLIB
    DISABLE_TOR
    USE_OPEN_SSL_FOR_ECDSA
    ALTBASE_ZANO_CORE_EXPORTS
    ALTBASE_RELEASE_BINARY=1
    MOBILE_WALLET_BUILD=1
  )
  target_include_directories(altbase_zano_core PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${ZANO_SOURCE_ROOT}/src"
    "${ZANO_SOURCE_ROOT}/contrib"
    "${ZANO_SOURCE_ROOT}/contrib/eos_portable_archive"
    "${ZANO_SOURCE_ROOT}/contrib/epee/include"
    "${ZANO_SOURCE_ROOT}/contrib/jwt-cpp/include"
    "${ZANO_MACOS_BOOST_ROOT}/Headers"
    "${ZANO_MACOS_OPENSSL_ROOT}/Headers"
    "${ZANO_MACOS_ICONV_ROOT}/Headers"
    "${ZANO_MACOS_VERSION_DIR}"
  )
  target_link_libraries(altbase_zano_core PRIVATE
    "${ZANO_MACOS_PLAIN_WALLET_LIB}"
    Threads::Threads
    "-framework Foundation"
    "-framework Security"
    "-framework CoreFoundation"
    "-framework SystemConfiguration"
    "-liconv"
  )
else()
  message(WARNING "Zano native libraries were not found; Zano privacy wallet will remain not-ready until Zano source is configured and built.")
endif()

set(ALTBASE_PRIVACY_WALLET_SOURCES
  src/coin_wallet_module.cpp
  src/wallet_secret.cpp
  src/protocol.cpp
)

function(altbase_add_privacy_wallet_module coin export_definition coin_definition)
  set(target "altbase_${coin}_wallet")
  if (coin STREQUAL "epic")
    add_library(${target} SHARED
      ${ALTBASE_PRIVACY_WALLET_SOURCES}
      src/epic_light_wallet_impl.cpp
    )
  else()
    add_library(${target} SHARED
      ${ALTBASE_PRIVACY_WALLET_SOURCES}
      src/privacy_light_wallet_impl.cpp
      src/native_http.cpp
    )
  endif()
  target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_definitions(${target} PRIVATE
    ${export_definition}
    ${coin_definition}=1
    ALTBASE_RELEASE_BINARY=1
    MOBILE_WALLET_BUILD=1
    NOMINMAX
  )
  if (NOT coin STREQUAL "epic")
    target_link_libraries(${target} PRIVATE secp256k1 altbase_net_core)
  endif()
  if (WIN32)
    target_link_libraries(${target} PRIVATE bcrypt)
  elseif(APPLE)
    target_include_directories(${target} PRIVATE "${ZANO_MACOS_OPENSSL_ROOT}/Headers")
    target_link_libraries(${target} PRIVATE
      "${ZANO_MACOS_OPENSSL_ROOT}/libopenssl.a"
      ${CMAKE_DL_LIBS}
    )
  else()
    target_link_libraries(${target} PRIVATE OpenSSL::Crypto ${CMAKE_DL_LIBS})
  endif()
  set_target_properties(${target} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  )
endfunction()

altbase_add_privacy_wallet_module(zano ALTBASE_ZANO_WALLET_EXPORTS ALTBASE_ZANO_WALLET_ONLY)
altbase_add_privacy_wallet_module(epic ALTBASE_EPIC_WALLET_EXPORTS ALTBASE_EPIC_WALLET_ONLY)
set_target_properties(altbase_epic_wallet PROPERTIES INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)

if (WIN32)
  if (NOT TARGET altbase_zano_core)
    message(FATAL_ERROR "Zano protocol core was not built; the Zano wallet module cannot be linked")
  endif()
  if (NOT EXISTS "${EPIC_WINDOWS_STATE_IMPORT_LIB}" OR NOT EXISTS "${EPIC_WINDOWS_SENDER_IMPORT_LIB}")
    message(FATAL_ERROR "Epic protocol module import libraries were not built")
  endif()
  target_link_libraries(altbase_zano_wallet PRIVATE altbase_zano_core)
  target_link_libraries(altbase_epic_wallet PRIVATE
    "${EPIC_WINDOWS_STATE_IMPORT_LIB}"
    "${EPIC_WINDOWS_SENDER_IMPORT_LIB}"
  )
  altbase_add_module_version(altbase_zano_wallet "altbase_zano_wallet.dll" "AltbaseZanoWallet" "Altbase Zano Wallet Module")
  altbase_add_module_version(altbase_epic_wallet "altbase_epic_wallet.dll" "AltbaseEpicWallet" "Altbase Epic Wallet Module")
endif()

target_link_libraries(altbase_core_bridge PRIVATE altbase_zano_wallet altbase_epic_wallet)
target_compile_definitions(altbase_core_bridge PRIVATE ALTBASE_SEPARATE_PRIVACY_MODULES=1)

target_include_directories(altbase_core_bridge PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if (MSVC)
  target_compile_options(altbase_core_bridge PRIVATE
    /W4
    /permissive-
    /EHsc
    /ZH:SHA_256
    /experimental:deterministic
    /Gy
    /Gw
    /GF
    "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../..=."
    "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/..=./native"
    "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/Zano=zano-src"
    "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/_install_windows/boost/x86_64/include=boost-include"
    "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/_install_windows/openssl/x86_64/include=openssl-include"
  )
  target_link_options(altbase_core_bridge PRIVATE
    /DYNAMICBASE
    /NXCOMPAT
    /HIGHENTROPYVA
    /CETCOMPAT
    /OPT:REF
    /OPT:ICF
    /MANIFEST:NO
    /RELEASE
  )
  foreach(core_target IN LISTS ALTBASE_LOCAL_CORE_TARGETS)
    target_compile_options(${core_target} PRIVATE
      /W4 /permissive- /EHsc /sdl /guard:cf /ZH:SHA_256 /experimental:deterministic /Gy /Gw /GF
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../..=."
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/..=./native"
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/Zano=zano-src"
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/_install_windows/boost/x86_64/include=boost-include"
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/_install_windows/openssl/x86_64/include=openssl-include"
    )
    target_link_options(${core_target} PRIVATE
      /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /CETCOMPAT /guard:cf
      /OPT:REF /OPT:ICF /INCREMENTAL:NO /RELEASE /Brepro
    )
  endforeach()
  foreach(utxo_module IN LISTS ALTBASE_UTXO_WALLET_MODULES)
    target_compile_options(${utxo_module} PRIVATE
      /W4
      /permissive-
      /EHsc
      /ZH:SHA_256
      /experimental:deterministic
      /Gy
      /Gw
      /GF
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../..=."
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/..=./native"
    )
    target_link_options(${utxo_module} PRIVATE
      /DYNAMICBASE
      /NXCOMPAT
      /HIGHENTROPYVA
      /CETCOMPAT
      /OPT:REF
      /OPT:ICF
      /RELEASE
    )
  endforeach()
  foreach(node_module IN LISTS ALTBASE_COIN_NODE_MODULES)
    target_compile_options(${node_module} PRIVATE
      /W4
      /permissive-
      /EHsc
      /ZH:SHA_256
      /experimental:deterministic
      /Gy
      /Gw
      /GF
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../..=."
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/..=./native"
    )
    target_link_options(${node_module} PRIVATE
      /DYNAMICBASE
      /NXCOMPAT
      /HIGHENTROPYVA
      /CETCOMPAT
      /OPT:REF
      /OPT:ICF
      /RELEASE
    )
  endforeach()
  if (TARGET altbase_zano_core)
    target_compile_options(altbase_zano_core PRIVATE
      /W4
      /permissive-
      /EHsc
      /ZH:SHA_256
      /experimental:deterministic
      /Gy
      /Gw
      /GF
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../..=."
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/..=./native"
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/Zano=zano-src"
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/_install_windows/boost/x86_64/include=boost-include"
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/_install_windows/openssl/x86_64/include=openssl-include"
    )
    target_link_options(altbase_zano_core PRIVATE
      /DYNAMICBASE
      /NXCOMPAT
      /HIGHENTROPYVA
      /CETCOMPAT
      /OPT:REF
      /OPT:ICF
      /RELEASE
    )
  endif()
  if (TARGET altbase_zano_wallet)
    target_compile_options(altbase_zano_wallet PRIVATE
      /W4
      /permissive-
      /EHsc
      /ZH:SHA_256
      /experimental:deterministic
      /Gy
      /Gw
      /GF
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../..=."
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/..=./native"
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/Zano=zano-src"
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/_install_windows/boost/x86_64/include=boost-include"
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../vendor/zano_native_lib/_install_windows/openssl/x86_64/include=openssl-include"
    )
    target_link_options(altbase_zano_wallet PRIVATE
      /DYNAMICBASE
      /NXCOMPAT
      /HIGHENTROPYVA
      /CETCOMPAT
      /OPT:REF
      /OPT:ICF
      /RELEASE
    )
  endif()
  if (TARGET altbase_epic_wallet)
    target_compile_options(altbase_epic_wallet PRIVATE
      /W4
      /permissive-
      /EHsc
      /sdl
      /guard:cf
      /ZH:SHA_256
      /experimental:deterministic
      /Gy
      /Gw
      /GF
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../..=."
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/..=./native"
    )
    target_link_options(altbase_epic_wallet PRIVATE
      /DYNAMICBASE
      /NXCOMPAT
      /HIGHENTROPYVA
      /CETCOMPAT
      /guard:cf
      /OPT:REF
      /OPT:ICF
      /INCREMENTAL:NO
      /RELEASE
      /Brepro
    )
  endif()
  if (TARGET altbase_net_core)
    target_compile_options(altbase_net_core PRIVATE
      /W4
      /permissive-
      /EHsc
      /ZH:SHA_256
      /experimental:deterministic
      /Gy
      /Gw
      /GF
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/../..=."
      "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}/..=./native"
    )
    target_link_options(altbase_net_core PRIVATE
      /DYNAMICBASE
      /NXCOMPAT
      /HIGHENTROPYVA
      /CETCOMPAT
      /OPT:REF
      /OPT:ICF
      /RELEASE
    )
  endif()
else()
  target_compile_options(altbase_core_bridge PRIVATE -Wall -Wextra -Wpedantic)
  foreach(utxo_service IN LISTS ALTBASE_UTXO_SERVICE_TARGETS)
    target_compile_options(${utxo_service} PRIVATE -Wall -Wextra -Wpedantic)
  endforeach()
  target_compile_options(altbase_wallet_vault PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(altbase_zano_wallet PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(altbase_epic_wallet PRIVATE -Wall -Wextra -Wpedantic)
  if (TARGET altbase_zano_core)
    target_compile_options(altbase_zano_core PRIVATE -Wall -Wextra -Wpedantic)
  endif()
  foreach(utxo_module IN LISTS ALTBASE_UTXO_WALLET_MODULES)
    target_compile_options(${utxo_module} PRIVATE -Wall -Wextra -Wpedantic -fvisibility=hidden)
  endforeach()
  foreach(node_module IN LISTS ALTBASE_COIN_NODE_MODULES)
    target_compile_options(${node_module} PRIVATE -Wall -Wextra -Wpedantic -fvisibility=hidden)
  endforeach()
endif()

set_target_properties(altbase_core_bridge PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if (BUILD_TESTING)
  add_executable(altbase_core_tests
    tests/core_tests.cpp
    src/address_validation.cpp
    src/protocol.cpp
    src/tx_planning.cpp
    src/wallet_derivation.cpp
    src/wallet_secret.cpp
  )
  target_include_directories(altbase_core_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(altbase_core_tests PRIVATE secp256k1)
  add_custom_command(TARGET altbase_core_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:secp256k1>
      $<TARGET_FILE_DIR:altbase_core_tests>
    VERBATIM
  )
  if (WIN32)
    target_link_libraries(altbase_core_tests PRIVATE bcrypt)
  elseif(APPLE)
    target_include_directories(altbase_core_tests PRIVATE "${ZANO_MACOS_OPENSSL_ROOT}/Headers")
    target_link_libraries(altbase_core_tests PRIVATE "${ZANO_MACOS_OPENSSL_ROOT}/libopenssl.a")
  else()
    target_link_libraries(altbase_core_tests PRIVATE OpenSSL::Crypto)
  endif()
  add_test(NAME altbase_core_tests COMMAND altbase_core_tests)
endif()

set_target_properties(${ALTBASE_LOCAL_CORE_TARGETS} PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

if (APPLE)
  set_target_properties(
    altbase_core_bridge
    ${ALTBASE_UTXO_SERVICE_TARGETS}
    altbase_wallet_vault
    altbase_net_core
    altbase_zano_wallet
    altbase_epic_wallet
    PROPERTIES
    BUILD_RPATH "@loader_path"
    INSTALL_RPATH "@loader_path"
  )
  if (TARGET altbase_zano_core)
    set_target_properties(altbase_zano_core PROPERTIES BUILD_RPATH "@loader_path" INSTALL_RPATH "@loader_path")
  endif()
elseif(UNIX)
  set_target_properties(
    altbase_core_bridge
    ${ALTBASE_UTXO_SERVICE_TARGETS}
    altbase_wallet_vault
    altbase_net_core
    altbase_zano_wallet
    altbase_epic_wallet
    PROPERTIES
    BUILD_RPATH "$ORIGIN"
    INSTALL_RPATH "$ORIGIN"
  )
  if (TARGET altbase_zano_core)
    set_target_properties(altbase_zano_core PROPERTIES BUILD_RPATH "$ORIGIN" INSTALL_RPATH "$ORIGIN")
  endif()
endif()

if (TARGET altbase_zano_core)
  set_target_properties(altbase_zano_core PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  )
endif()

if (TARGET altbase_zano_wallet)
  set_target_properties(altbase_zano_wallet PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  )
endif()

if (TARGET altbase_epic_wallet)
  set_target_properties(altbase_epic_wallet PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  )
endif()

if (TARGET altbase_net_core)
  set_target_properties(altbase_net_core PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  )
endif()

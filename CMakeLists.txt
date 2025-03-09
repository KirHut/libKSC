## The KirHut Security Center Library
## CMake Main File
##
## Copyright © KirHut Software Company
cmake_minimum_required(VERSION 3.21)

# Enable Hot Reload for MSVC compilers if supported.
if(POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    string(CONCAT KIRHUT_MSVC_DEBUG_HOTRELOAD
        "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,"
        "$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>"
    )
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT
        ${KIRHUT_MSVC_DEBUG_HOTRELOAD}
    )
endif()

project(libKSC
    VERSION 0.1
    LANGUAGES CXX
    DESCRIPTION "The KirHut Security Center Shared Library"
)

include(cmake/get_cpm.cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(KSC_LIB_BUILD_TESTS "Build the tests for this library." OFF)

if(MSVC)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

find_package(Qt6
    REQUIRED COMPONENTS
        Core
        Concurrent
        Test
)

CPMAddPackage(
    NAME                libKirHut
    VERSION             0.1
    GITHUB_REPOSITORY   KirHut/libKirHut
    OPTIONS
        "KH_MD5_SUPPORT ON"
        "KH_USES_QT ON"
)

CPMAddPackage(
    NAME            cryptopp-cmake
    GIT_REPOSITORY  "https://github.com/abdes/cryptopp-cmake.git"
    GIT_TAG         "CRYPTOPP_8_9_0"
    OPTIONS         "CRYPTOPP_BUILD_TESTING OFF" "CRYPTOPP_INSTALL OFF"
)

CPMAddPackage("gh:ArthurSonzogni/FTXUI@5.0.0")

qt_standard_project_setup(
    REQUIRES 6.5
    SUPPORTS_UP_TO 6.8
)

set(libKSC_EXTERN_HEADERS
    md6.hpp
)

set(libKSC_EXTERN_SOURCES
    md6_compress.cpp
    md6_mode.cpp
)

list(TRANSFORM libKSC_EXTERN_HEADERS PREPEND "include/")

set(libKSC_EXTERN
    ${libKSC_EXTERN_HEADERS}
    ${libKSC_EXTERN_SOURCES}
)

list(TRANSFORM libKSC_EXTERN PREPEND "extern/")

set(libKSC_PRIVATE_HEADERS
    base.hpp
)

set(libKSC_LIBRARY_HEADERS
    base.hpp
    cipherunicorn.hpp
	signalemitter.hpp
)

list(TRANSFORM libKSC_LIBRARY_HEADERS PREPEND "include/ksc/")
list(TRANSFORM libKSC_PRIVATE_HEADERS PREPEND "priv/priv/")

set(libKSC_HEADERS
    ${libKSC_LIBRARY_HEADERS}
    ${libKSC_PRIVATE_HEADERS}
)

set(libKSC_SOURCES
    cipherunicorn.cpp
	signalemitter.cpp
)

list(TRANSFORM libKSC_SOURCES PREPEND "src/")

qt_add_library (libKSC SHARED
    ${libKSC_HEADERS}
    ${libKSC_SOURCES}
    ${libKSC_EXTERN}
)
add_library(KirHut::libKSC ALIAS libKSC)

target_include_directories(libKSC PUBLIC "include")
target_include_directories(libKSC PRIVATE "extern/include" "priv")

set(libKSC_PUBLIC_LIBRARIES
    KirHut::libKirHut
    Qt6::Core
    Qt6::Concurrent
	cryptopp::cryptopp
	ftxui::screen
	ftxui::dom
	ftxui::component
)

if(KSC_LIB_BUILD_TESTS)
    add_subdirectory(test)
endif()

target_link_libraries(libKSC
    PUBLIC ${libKSC_PUBLIC_LIBRARIES}
)

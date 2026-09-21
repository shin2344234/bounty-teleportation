cmake_minimum_required(VERSION 3.20)
project(BountyProbe LANGUAGES CXX)

# Bounty Probe: a research ASI plugin for Crimson Desert 2.03.00. It watches
# the field-move handler that refuses a fast travel while the player is
# carrying something, and the catch machinery that owns what is carried.
#
# The hooking core (log, paths, mem, farhook, sites) is Flight Freedom's,
# copied rather than shared because the two plugins version separately and a
# probe that stops building when its neighbour changes is worth nothing. The
# namespace is bp:: here and fp:: there; everything else is the same code, and
# a fix in one is worth carrying to the other by hand.

if(NOT WIN32)
    message(FATAL_ERROR "Bounty Probe targets Windows only.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>") # static CRT, no redist needed

include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)

# MinHook is here only for its HDE64 length decoder, which farhook uses to
# measure the bytes it steals. No MinHook hook is ever created.
FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(minhook)

# BountyProbe.ini's own bytes as a header, so the documented ini can be written
# beside the plugin on first run without a second copy of the text going out of
# step with the first. It reads and writes HEX: carrying the bytes through
# CMake as a string rewrites every LF into CRLF.
set(BP_INI_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated/ini_default.h")
add_custom_command(
    OUTPUT "${BP_INI_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/generated"
    COMMAND ${CMAKE_COMMAND} "-DIN=${CMAKE_CURRENT_SOURCE_DIR}/BountyProbe.ini"
                             "-DOUT=${BP_INI_HEADER}"
                             -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_ini.cmake"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/BountyProbe.ini"
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_ini.cmake"
    COMMENT "Embedding BountyProbe.ini"
    VERBATIM
)

add_library(BountyProbe SHARED
    "${BP_INI_HEADER}"
    src/dllmain.cpp
    src/core/mod.cpp
    src/core/log.cpp
    src/core/paths.cpp
    src/game/mem.cpp
    src/game/farhook.cpp
    src/game/dump.cpp
    src/game/errors.cpp
    src/game/resolve.cpp
    src/game/sites.cpp
    src/game/holdwatch.cpp
    src/game/keepcarried.cpp
    src/game/catchwatch.cpp
    src/game/unwind.cpp
)

target_include_directories(BountyProbe PRIVATE src "${CMAKE_CURRENT_BINARY_DIR}/generated" ${minhook_SOURCE_DIR}/src/hde)
target_link_libraries(BountyProbe PRIVATE minhook)
target_compile_definitions(BountyProbe PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_compile_options(BountyProbe PRIVATE /utf-8 /W3)

set_target_properties(BountyProbe PROPERTIES PREFIX "" SUFFIX ".asi" OUTPUT_NAME "BountyProbe")

if(MSVC)
    target_compile_options(BountyProbe PRIVATE /guard:cf)
    target_link_options(BountyProbe PRIVATE /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf)
endif()

# The site hooks, exercised against functions inside the test binary itself.
# Flight Freedom's harness, carried over with the core it tests.
add_executable(SitesTest
    tests/sites_test.cpp
    src/core/log.cpp
    src/core/paths.cpp
    src/game/mem.cpp
    src/game/farhook.cpp
    src/game/dump.cpp
    src/game/errors.cpp
    src/game/resolve.cpp
    src/game/sites.cpp
    src/game/holdwatch.cpp
    src/game/keepcarried.cpp
    src/game/catchwatch.cpp
    src/game/unwind.cpp
)
target_include_directories(SitesTest PRIVATE src ${minhook_SOURCE_DIR}/src/hde)
target_link_libraries(SitesTest PRIVATE minhook)
target_compile_definitions(SitesTest PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_compile_options(SitesTest PRIVATE /utf-8 /W3 /EHsc)

add_custom_command(TARGET BountyProbe POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/dist"
    COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:BountyProbe>" "${CMAKE_SOURCE_DIR}/dist/"
    COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/BountyProbe.ini" "${CMAKE_SOURCE_DIR}/dist/"
    COMMENT "Staging dist/"
    VERBATIM
)

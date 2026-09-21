cmake_minimum_required(VERSION 3.20)
project(BountyTeleportation LANGUAGES CXX)

# Bounty Teleportation: the shipping half of this repo. Bounty Probe next door found
# the four patches and the one hook; this applies them and does nothing else.
# It has no sites, no dumps, no watchers and no error table, and its log is a
# few lines a session against the probe's half a gigabyte a minute.
#
# Five source files are the probe's and are compiled from ..\mod\src rather
# than copied: log, paths, mem, farhook and keepcarried. A fix in any of them
# belongs to both plugins and copying would mean fixing it twice. Everything
# the probe uses to research rather than to work is left out of the build.

if(NOT WIN32)
    message(FATAL_ERROR "Bounty Teleportation targets Windows only.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>") # static CRT, no redist needed

set(PROBE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../mod/src")
if(NOT EXISTS "${PROBE_SRC}/game/farhook.cpp")
    message(FATAL_ERROR "Bounty Probe's sources are not at ${PROBE_SRC}; the two projects sit side by side.")
endif()

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

# BountyTeleportation.ini's own bytes as a header, so the plugin can write the
# documented ini beside itself on a first run without a second copy of that
# text going out of step with the first. The archive ships the same file.
set(BT_INI_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated/ini_default.h")
add_custom_command(
    OUTPUT "${BT_INI_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/generated"
    COMMAND ${CMAKE_COMMAND} "-DIN=${CMAKE_CURRENT_SOURCE_DIR}/BountyTeleportation.ini"
                             "-DOUT=${BT_INI_HEADER}"
                             -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_ini.cmake"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/BountyTeleportation.ini"
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_ini.cmake"
    COMMENT "Embedding BountyTeleportation.ini"
    VERBATIM
)

add_library(BountyTeleportation SHARED
    "${BT_INI_HEADER}"
    src/dllmain.cpp
    src/mod.cpp
    src/patch.cpp
    "${PROBE_SRC}/core/log.cpp"
    "${PROBE_SRC}/core/paths.cpp"
    "${PROBE_SRC}/game/mem.cpp"
    "${PROBE_SRC}/game/farhook.cpp"
    "${PROBE_SRC}/game/keepcarried.cpp"
)

target_include_directories(BountyTeleportation PRIVATE src "${PROBE_SRC}"
                           "${CMAKE_CURRENT_BINARY_DIR}/generated" ${minhook_SOURCE_DIR}/src/hde)
target_link_libraries(BountyTeleportation PRIVATE minhook)
target_compile_definitions(BountyTeleportation PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_compile_options(BountyTeleportation PRIVATE /utf-8 /W3)

set_target_properties(BountyTeleportation PROPERTIES PREFIX "" SUFFIX ".asi" OUTPUT_NAME "BountyTeleportation")

if(MSVC)
    target_compile_options(BountyTeleportation PRIVATE /guard:cf)
    target_link_options(BountyTeleportation PRIVATE /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf)
endif()

add_custom_command(TARGET BountyTeleportation POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/dist"
    COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:BountyTeleportation>" "${CMAKE_SOURCE_DIR}/dist/"
    COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/BountyTeleportation.ini" "${CMAKE_SOURCE_DIR}/dist/"
    COMMENT "Staging dist/"
    VERBATIM
)

cmake_minimum_required(VERSION 3.19)
project(cef-pulse-auth)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# CEF root directory (set by Nix)
set(CEF_ROOT "$ENV{CEF_ROOT}" CACHE PATH "CEF root directory")

# Include CEF cmake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CEF_ROOT}/cmake")

# Find CEF first (this loads cef_variables.cmake internally)
find_package(CEF REQUIRED)

# Include CEF headers
include_directories(${CEF_ROOT})

# Build libcef_dll_wrapper
add_subdirectory(${CEF_ROOT}/libcef_dll ${CMAKE_BINARY_DIR}/libcef_dll_wrapper)

# Main executable
add_executable(cef-pulse-auth main.cc)

# Link against CEF
target_link_libraries(cef-pulse-auth
    libcef_dll_wrapper
    ${CEF_ROOT}/Release/libcef.so
    pthread
)

# Copy resources
add_custom_command(TARGET cef-pulse-auth POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CEF_ROOT}/Resources
        $<TARGET_FILE_DIR:cef-pulse-auth>
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CEF_ROOT}/Release
        $<TARGET_FILE_DIR:cef-pulse-auth>
)

install(TARGETS cef-pulse-auth DESTINATION bin)
install(DIRECTORY ${CEF_ROOT}/Resources/ DESTINATION lib/cef)
install(DIRECTORY ${CEF_ROOT}/Release/ DESTINATION lib/cef
    USE_SOURCE_PERMISSIONS
    PATTERN "*.so" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

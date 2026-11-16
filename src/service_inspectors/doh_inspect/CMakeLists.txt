set(DOH_SOURCES
    doh_inspect.cc
    doh_inspect.h
    doh_module.cc
    doh_module.h
    doh_parser.cc
    doh_parser.h
)

add_library(doh_inspect OBJECT ${DOH_SOURCES})

target_include_directories(doh_inspect PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if (ENABLE_UNIT_TESTS)
    add_subdirectory(test)
endif ()

add_cpputest(doh_parser_test
    SOURCES
        ../doh_parser.cc
)

add_cpputest(doh_pcap_test
    SOURCES
        ../doh_parser.cc
)

target_compile_definitions(doh_pcap_test PRIVATE
    DOH_PCAP_PATH="${CMAKE_CURRENT_SOURCE_DIR}/doh_inspect.pcap"
)

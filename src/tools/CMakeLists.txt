add_library(tools pcap_editor.c pcap_reader.c)
target_include_directories(tools PRIVATE headers)
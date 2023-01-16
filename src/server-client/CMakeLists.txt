add_library(server-client simulation_server.c simulator_client.c)
target_include_directories(server-client PRIVATE headers)
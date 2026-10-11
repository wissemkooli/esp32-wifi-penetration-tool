idf_component_register(SRCS "frame_analyzer.c" "frame_analyzer_parser.c"
                    INCLUDE_DIRS "interface"
                    REQUIRES esp_wifi esp_event
                    PRIV_REQUIRES wifi_controller)

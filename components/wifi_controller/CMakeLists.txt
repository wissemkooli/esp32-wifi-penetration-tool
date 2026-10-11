idf_component_register(SRCS "sniffer.c" "ap_scanner.c" "wifi_controller.c" "security_report.c"
                    INCLUDE_DIRS "interface" "."
                    REQUIRES esp_wifi esp_event esp_netif freertos)

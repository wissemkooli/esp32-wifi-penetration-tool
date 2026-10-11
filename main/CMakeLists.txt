idf_component_register(SRCS "attack_dos.c" "attack_method.c" "main.c" "attack_handshake.c" "attack_pmkid.c" "attack.c"
                           "controller.c" "serial_console.c" "serial_task.c"
                    INCLUDE_DIRS .
                    REQUIRES esp_wifi
    PRIV_REQUIRES esp_timer esp_event esp_hw_support esp_rom freertos wifi_controller webserver
                                  frame_analyzer pcap_serializer hccapx_serializer wsl_bypasser)

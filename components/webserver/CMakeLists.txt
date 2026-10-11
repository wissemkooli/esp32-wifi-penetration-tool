idf_component_register(SRCS "webserver.c"
                    INCLUDE_DIRS "interface"
                    PRIV_INCLUDE_DIRS "${CMAKE_CURRENT_BINARY_DIR}"
                    REQUIRES esp_event
    PRIV_REQUIRES hccapx_serializer pcap_serializer esp_http_server esp_timer json wifi_controller main)

set(PAGE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/page_index.h")
set(ASSET_HEADER "${CMAKE_CURRENT_BINARY_DIR}/web_assets.h")
find_program(NPM_EXECUTABLE NAMES npm.cmd npm REQUIRED)
file(GLOB WEB_SOURCE CONFIGURE_DEPENDS "${PROJECT_DIR}/web/*.js" "${PROJECT_DIR}/web/*.html" "${PROJECT_DIR}/web/*.css")
add_custom_command(OUTPUT "${PROJECT_DIR}/web/dist/index.html" "${PROJECT_DIR}/web/dist/dashboard.js"
                          "${PROJECT_DIR}/web/dist/audit-worker.js" "${PROJECT_DIR}/web/dist/style.css" "${PROJECT_DIR}/web/dist/licenses.txt"
    COMMAND "${NPM_EXECUTABLE}" run build
    WORKING_DIRECTORY "${PROJECT_DIR}"
    DEPENDS ${WEB_SOURCE} "${PROJECT_DIR}/tools/build_web.mjs" "${PROJECT_DIR}/package-lock.json" "${PROJECT_DIR}/web/vendor/HASH-WASM-LICENSE" "${PROJECT_DIR}/LICENSE"
    VERBATIM)
add_custom_command(OUTPUT "${PAGE_HEADER}"
    COMMAND "${PYTHON}" "${PROJECT_DIR}/tools/embed_page.py" --output "${PAGE_HEADER}"
    DEPENDS "${PROJECT_DIR}/tools/embed_page.py" "${PROJECT_DIR}/web/dist/index.html"
    VERBATIM)
add_custom_command(OUTPUT "${ASSET_HEADER}"
    COMMAND "${PYTHON}" "${PROJECT_DIR}/tools/embed_assets.py" --output "${ASSET_HEADER}"
    DEPENDS "${PROJECT_DIR}/tools/embed_assets.py" "${PROJECT_DIR}/web/dist/dashboard.js"
            "${PROJECT_DIR}/web/dist/audit-worker.js" "${PROJECT_DIR}/web/dist/style.css" "${PROJECT_DIR}/web/dist/licenses.txt"
    VERBATIM)
add_custom_target(embedded_web_page DEPENDS "${PAGE_HEADER}" "${ASSET_HEADER}")
add_dependencies(${COMPONENT_LIB} embedded_web_page)

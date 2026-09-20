cmake_minimum_required(VERSION 3.20)
project(CheatWizard VERSION 1.7.3 LANGUAGES CXX)

set(CW_ENGINE_BUILDER_PAYLOAD "" CACHE FILEPATH "Prepared standalone engine-builder payload ZIP")
set(CW_PRODUCT_BUILDER_PAYLOAD "" CACHE FILEPATH "Prepared standalone product-builder payload ZIP")

if(MSVC)
    # Keep all first-party libraries/executables on one portable CRT model.
    # Frontends and engine are distributed without a separate VC runtime install.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include(CTest)

add_library(cw_core STATIC
    src/Value.cpp
    src/AobPattern.cpp
    src/AobPersistence.cpp
    src/ScanPersistence.cpp
    src/RelativeAddress.cpp
    src/InstructionDecode.cpp
    src/PointerAlgorithms.cpp
    src/PointerPersistence.cpp
    src/PointerProfile.cpp
    src/PointerMap.cpp
)
target_include_directories(cw_core PUBLIC include)
target_compile_features(cw_core PUBLIC cxx_std_20)

add_library(cw_ipc STATIC
    src/EngineProtocol.cpp
)
target_include_directories(cw_ipc PUBLIC include)
target_compile_features(cw_ipc PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(cw_ipc PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(cw_ipc PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
    target_sources(cw_core PRIVATE src/Win32Error.cpp)

    # Live-process engine implementation. Frontends must consume this only
    # through the engine boundary; cw_cli links it temporarily during the
    # migration until IPC replaces direct in-process calls.
    add_library(cw_engine_core STATIC
        src/EngineSession.cpp
        src/ProcessManager.cpp
        src/MemoryScanner.cpp
        src/AobScanner.cpp
        src/MemoryWriter.cpp
        src/FreezeManager.cpp
        src/PointerScanner.cpp
    )
    target_link_libraries(cw_engine_core PUBLIC cw_core)
    target_include_directories(cw_engine_core PUBLIC include)
    target_compile_features(cw_engine_core PUBLIC cxx_std_20)
    target_compile_definitions(cw_engine_core PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(cw_engine_core PRIVATE /W4 /permissive- /EHsc)
    else()
        target_compile_options(cw_engine_core PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_library(cw_ipc_win STATIC
        src/EnginePipe.cpp
    )
    target_link_libraries(cw_ipc_win PUBLIC cw_ipc PRIVATE advapi32)
    target_include_directories(cw_ipc_win PUBLIC include)
    target_compile_features(cw_ipc_win PUBLIC cxx_std_20)
    target_compile_definitions(cw_ipc_win PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(cw_ipc_win PRIVATE /W4 /permissive- /EHsc)
    else()
        target_compile_options(cw_ipc_win PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_library(cw_ipc_client STATIC
        src/EngineClient.cpp
        src/EngineFrontend.cpp
    )
    target_link_libraries(cw_ipc_client PUBLIC cw_ipc_win cw_core PRIVATE bcrypt)
    target_include_directories(cw_ipc_client PUBLIC include)
    target_compile_features(cw_ipc_client PUBLIC cxx_std_20)
    target_compile_definitions(cw_ipc_client PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(cw_ipc_client PRIVATE /W4 /permissive- /EHsc)
    else()
        target_compile_options(cw_ipc_client PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()

if(MSVC)
    target_compile_options(cw_core PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(cw_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(BUILD_TESTING)
    add_executable(cw_core_tests tests/CoreTests.cpp)
    if(WIN32)
        target_link_libraries(cw_core_tests PRIVATE cw_engine_core)
    endif()
    target_link_libraries(cw_core_tests PRIVATE cw_core)
    target_compile_features(cw_core_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(cw_core_tests PRIVATE /W4 /permissive- /EHsc)
    else()
        target_compile_options(cw_core_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME cw_core_tests COMMAND cw_core_tests)

    add_executable(cw_engine_protocol_tests tests/EngineProtocolTests.cpp)
    target_link_libraries(cw_engine_protocol_tests PRIVATE cw_ipc)
    target_include_directories(cw_engine_protocol_tests PRIVATE include)
    target_compile_features(cw_engine_protocol_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(cw_engine_protocol_tests PRIVATE /W4 /permissive- /EHsc)
    else()
        target_compile_options(cw_engine_protocol_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME cw_engine_protocol_tests COMMAND cw_engine_protocol_tests)

    if(WIN32)
        add_executable(cw_engine_session_tests tests/EngineSessionTests.cpp)
        target_link_libraries(cw_engine_session_tests PRIVATE cw_engine_core)
        target_include_directories(cw_engine_session_tests PRIVATE include)
        target_compile_features(cw_engine_session_tests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(cw_engine_session_tests PRIVATE /W4 /permissive- /EHsc)
        else()
            target_compile_options(cw_engine_session_tests PRIVATE -Wall -Wextra -Wpedantic)
        endif()
        add_test(NAME cw_engine_session_tests COMMAND cw_engine_session_tests)

        add_executable(cw_engine_pipe_tests tests/EnginePipeTests.cpp)
        target_link_libraries(cw_engine_pipe_tests PRIVATE cw_ipc_win)
        target_include_directories(cw_engine_pipe_tests PRIVATE include)
        target_compile_features(cw_engine_pipe_tests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(cw_engine_pipe_tests PRIVATE /W4 /permissive- /EHsc)
        else()
            target_compile_options(cw_engine_pipe_tests PRIVATE -Wall -Wextra -Wpedantic)
        endif()
        add_test(NAME cw_engine_pipe_tests COMMAND cw_engine_pipe_tests)

        add_executable(cw_engine_process_tests tests/EngineProcessTests.cpp)
        target_link_libraries(cw_engine_process_tests PRIVATE cw_ipc_win)
        target_include_directories(cw_engine_process_tests PRIVATE include)
        target_compile_features(cw_engine_process_tests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(cw_engine_process_tests PRIVATE /W4 /permissive- /EHsc)
        else()
            target_compile_options(cw_engine_process_tests PRIVATE -Wall -Wextra -Wpedantic)
        endif()
        add_test(NAME cw_engine_process_tests COMMAND cw_engine_process_tests $<TARGET_FILE:cw_engine>)

        add_executable(cw_engine_owner_death_tests tests/EngineOwnerDeathTests.cpp)
        target_link_libraries(cw_engine_owner_death_tests PRIVATE cw_ipc_win)
        target_include_directories(cw_engine_owner_death_tests PRIVATE include)
        target_compile_features(cw_engine_owner_death_tests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(cw_engine_owner_death_tests PRIVATE /W4 /permissive- /EHsc)
        else()
            target_compile_options(cw_engine_owner_death_tests PRIVATE -Wall -Wextra -Wpedantic)
        endif()
        add_test(NAME cw_engine_owner_death_tests COMMAND cw_engine_owner_death_tests $<TARGET_FILE:cw_engine>)

        add_executable(cw_engine_client_tests tests/EngineClientTests.cpp)
        target_link_libraries(cw_engine_client_tests PRIVATE cw_ipc_client)
        target_include_directories(cw_engine_client_tests PRIVATE include)
        target_compile_features(cw_engine_client_tests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(cw_engine_client_tests PRIVATE /W4 /permissive- /EHsc)
        else()
            target_compile_options(cw_engine_client_tests PRIVATE -Wall -Wextra -Wpedantic)
        endif()
        add_test(NAME cw_engine_client_tests COMMAND cw_engine_client_tests $<TARGET_FILE:cw_engine>)

        add_executable(cw_cli_target tests/CliTarget.cpp)
        target_compile_features(cw_cli_target PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(cw_cli_target PRIVATE /W4 /permissive- /EHsc)
        else()
            target_compile_options(cw_cli_target PRIVATE -Wall -Wextra -Wpedantic)
        endif()

        add_executable(cw_cli_frontend_tests tests/CliFrontendTests.cpp)
        target_compile_features(cw_cli_frontend_tests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(cw_cli_frontend_tests PRIVATE /W4 /permissive- /EHsc)
        else()
            target_compile_options(cw_cli_frontend_tests PRIVATE -Wall -Wextra -Wpedantic)
        endif()
        add_dependencies(cw_cli_frontend_tests cw_cli cw_engine cw_cli_target)
        add_test(NAME cw_cli_frontend_tests COMMAND cw_cli_frontend_tests $<TARGET_FILE:cw_cli> $<TARGET_FILE:cw_cli_target>)
    endif()

    if(NOT WIN32)
        add_executable(cw_mock_scanner_tests
            tests/MockWin32ScannerTests.cpp
            src/MemoryScanner.cpp
        )
        target_link_libraries(cw_mock_scanner_tests PRIVATE cw_core)
        target_include_directories(cw_mock_scanner_tests PRIVATE tests/win32_stubs include)
        target_compile_features(cw_mock_scanner_tests PRIVATE cxx_std_20)
        target_compile_options(cw_mock_scanner_tests PRIVATE -Wall -Wextra -Wpedantic)
        add_test(NAME cw_mock_scanner_tests COMMAND cw_mock_scanner_tests)

        add_executable(cw_mock_aob_tests
            tests/MockAobScannerTests.cpp
            src/AobScanner.cpp
        )
        target_link_libraries(cw_mock_aob_tests PRIVATE cw_core)
        target_include_directories(cw_mock_aob_tests PRIVATE tests/win32_stubs include)
        target_compile_features(cw_mock_aob_tests PRIVATE cxx_std_20)
        target_compile_options(cw_mock_aob_tests PRIVATE -Wall -Wextra -Wpedantic)
        add_test(NAME cw_mock_aob_tests COMMAND cw_mock_aob_tests)

    endif()

    # PointerScanner is exercised against deterministic Win32 stubs on every
    # host, including Windows. This keeps targeted/index-fallback regressions in
    # the release CI path instead of only in non-Windows developer builds.
    add_executable(cw_mock_pointer_tests
        tests/MockPointerScannerTests.cpp
        src/PointerScanner.cpp
    )
    target_link_libraries(cw_mock_pointer_tests PRIVATE cw_core)
    target_include_directories(cw_mock_pointer_tests PRIVATE tests/win32_stubs include)
    target_compile_features(cw_mock_pointer_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(cw_mock_pointer_tests PRIVATE /W4 /permissive- /EHsc)
    else()
        target_compile_options(cw_mock_pointer_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME cw_mock_pointer_tests COMMAND cw_mock_pointer_tests)
endif()

if(WIN32)
    enable_language(RC)

    function(cw_add_version_resource target original_filename file_description internal_name)
        file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/resources/cheat-wizard.ico" CW_ICON_RC)
        set(CW_ORIGINAL_FILENAME "${original_filename}")
        set(CW_FILE_DESCRIPTION "${file_description}")
        set(CW_INTERNAL_NAME "${internal_name}")
        set(version_rc "${CMAKE_CURRENT_BINARY_DIR}/generated/${target}-version.rc")
        configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/resources/CheatWizardVersion.rc.in"
            "${version_rc}"
            @ONLY)
        target_sources(${target} PRIVATE "${version_rc}")
    endfunction()

    function(cw_harden_windows_target target)
        if(MSVC)
            target_compile_options(${target} PRIVATE /guard:cf)
            target_link_options(${target} PRIVATE
                /guard:cf
                /CETCOMPAT
                /DYNAMICBASE
                /HIGHENTROPYVA
                /NXCOMPAT)
        endif()
    endfunction()

    add_executable(cw_engine
        src/EngineMain.cpp
    )
    set_target_properties(cw_engine PROPERTIES OUTPUT_NAME "cw-engine")
    cw_add_version_resource(cw_engine "cw-engine.exe" "Cheat Wizard Engine" "cw-engine")
    cw_harden_windows_target(cw_engine)
    target_link_libraries(cw_engine PRIVATE cw_engine_core cw_ipc_win)
    target_include_directories(cw_engine PRIVATE include)
    target_compile_features(cw_engine PRIVATE cxx_std_20)
    target_compile_definitions(cw_engine PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(cw_engine PRIVATE /W4 /permissive- /EHsc /GS)
    else()
        target_compile_options(cw_engine PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    if(CW_ENGINE_BUILDER_PAYLOAD)
        get_filename_component(CW_ENGINE_BUILDER_PAYLOAD_ABS "${CW_ENGINE_BUILDER_PAYLOAD}" ABSOLUTE)
        if(NOT EXISTS "${CW_ENGINE_BUILDER_PAYLOAD_ABS}")
            message(FATAL_ERROR "CW_ENGINE_BUILDER_PAYLOAD does not exist: ${CW_ENGINE_BUILDER_PAYLOAD_ABS}")
        endif()
        file(TO_CMAKE_PATH "${CW_ENGINE_BUILDER_PAYLOAD_ABS}" CW_ENGINE_BUILDER_PAYLOAD_RC)
        set(engine_builder_payload_rc "${CMAKE_CURRENT_BINARY_DIR}/generated/cw-engine-builder-payload.rc")
        configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/resources/EngineBuilderPayload.rc.in"
            "${engine_builder_payload_rc}"
            @ONLY)

        add_executable(cw_engine_builder
            src/EngineBuilderMain.cpp
            "${engine_builder_payload_rc}")
        set_target_properties(cw_engine_builder PROPERTIES OUTPUT_NAME "cw-engine-builder")
        cw_add_version_resource(
            cw_engine_builder
            "cw-engine-builder.exe"
            "Cheat Wizard Engine Builder"
            "cw-engine-builder")
        cw_harden_windows_target(cw_engine_builder)
        target_compile_features(cw_engine_builder PRIVATE cxx_std_20)
        target_compile_definitions(cw_engine_builder PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
        target_link_libraries(cw_engine_builder PRIVATE bcrypt)
        if(MSVC)
            target_compile_options(cw_engine_builder PRIVATE /W4 /permissive- /EHsc /GS)
        else()
            target_compile_options(cw_engine_builder PRIVATE -Wall -Wextra -Wpedantic)
        endif()
    else()
        message(STATUS "CW Engine Builder disabled: prepare payload with scripts/Prepare-EngineBuilderPayload.ps1 and set CW_ENGINE_BUILDER_PAYLOAD")
    endif()

    if(CW_PRODUCT_BUILDER_PAYLOAD)
        get_filename_component(CW_PRODUCT_BUILDER_PAYLOAD_ABS "${CW_PRODUCT_BUILDER_PAYLOAD}" ABSOLUTE)
        if(NOT EXISTS "${CW_PRODUCT_BUILDER_PAYLOAD_ABS}")
            message(FATAL_ERROR "CW_PRODUCT_BUILDER_PAYLOAD does not exist: ${CW_PRODUCT_BUILDER_PAYLOAD_ABS}")
        endif()
        file(TO_CMAKE_PATH "${CW_PRODUCT_BUILDER_PAYLOAD_ABS}" CW_PRODUCT_BUILDER_PAYLOAD_RC)
        set(product_builder_payload_rc "${CMAKE_CURRENT_BINARY_DIR}/generated/cw-product-builder-payload.rc")
        configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/resources/ProductBuilderPayload.rc.in"
            "${product_builder_payload_rc}"
            @ONLY)

        add_executable(cw_product_builder WIN32
            src/ProductBuilderMain.cpp
            "${product_builder_payload_rc}")
        set_target_properties(cw_product_builder PROPERTIES OUTPUT_NAME "Cheat-Wizard-Builder")
        cw_add_version_resource(
            cw_product_builder
            "Cheat-Wizard-Builder.exe"
            "Cheat Wizard Standalone Builder"
            "Cheat-Wizard-Builder")
        cw_harden_windows_target(cw_product_builder)
        target_compile_features(cw_product_builder PRIVATE cxx_std_20)
        target_compile_definitions(cw_product_builder PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
        target_link_libraries(cw_product_builder PRIVATE bcrypt shell32 user32 gdi32 comctl32)
        if(MSVC)
            target_compile_options(cw_product_builder PRIVATE /W4 /permissive- /EHsc /GS)
        else()
            target_compile_options(cw_product_builder PRIVATE -Wall -Wextra -Wpedantic)
        endif()
    else()
        message(STATUS "Cheat Wizard Product Builder disabled: prepare payload with scripts/Prepare-ProductBuilderPayload.ps1 and set CW_PRODUCT_BUILDER_PAYLOAD")
    endif()

    add_executable(cw_cli
        src/main.cpp
    )
    set_target_properties(cw_cli PROPERTIES OUTPUT_NAME "cw")
    cw_add_version_resource(cw_cli "cw.exe" "Cheat Wizard Command Line" "cw")
    cw_harden_windows_target(cw_cli)
    target_link_libraries(cw_cli PRIVATE cw_ipc_client)
    target_include_directories(cw_cli PRIVATE include)
    target_compile_features(cw_cli PRIVATE cxx_std_20)
    target_compile_definitions(cw_cli PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

    if(MSVC)
        target_compile_options(cw_cli PRIVATE /W4 /permissive- /EHsc)
    else()
        target_compile_options(cw_cli PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        message(WARNING "Cheat Wizard is being built as 32-bit. x64 is recommended for scanning modern Windows processes.")
    endif()

    # Native Win32 GUI. The application logic remains allocation-light/custom-rendered,
    # but official MSVC builds use the standard statically linked CRT entry path.
    add_executable(cw_gui WIN32
        portable_win/CW_GUI_NoCRT.cpp
        portable_win/GuiEngineBridge.cpp
        portable_win/StandardCRTEntry.cpp)
    set_target_properties(cw_gui PROPERTIES OUTPUT_NAME "Cheat Wizard")
    cw_add_version_resource(cw_gui "Cheat Wizard.exe" "Cheat Wizard" "cw-gui")
    cw_harden_windows_target(cw_gui)
    target_compile_features(cw_gui PRIVATE cxx_std_20)
    target_compile_definitions(cw_gui PRIVATE CW_USE_STANDARD_CRT=1 CW_CRT_ENTRY_GUI=1)
    set_property(TARGET cw_gui PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_link_libraries(cw_gui PRIVATE cw_ipc_client kernel32 user32 gdi32 msimg32)
    if(MSVC)
        add_custom_command(TARGET cw_gui POST_BUILD
            COMMAND dumpbin /imports "$<TARGET_FILE:cw_gui>" > "${CMAKE_CURRENT_BINARY_DIR}/cw-gui-imports.txt"
            COMMAND ${CMAKE_COMMAND}
                -DINPUT=${CMAKE_CURRENT_BINARY_DIR}/cw-gui-imports.txt
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/AuditGuiImports.cmake"
            VERBATIM)
    endif()
    add_custom_command(TARGET cw_gui POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/locales"
            "$<TARGET_FILE_DIR:cw_gui>/locales"
        VERBATIM)
    if(MSVC)
        target_compile_options(cw_gui PRIVATE /W4 /permissive- /EHsc /GS)
    else()
        target_compile_options(cw_gui PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    # Native standalone trainer runtime template. trainer-builder embeds this
    # PE into itself, then appends a validated trainer package to produce one
    # distributable EXE with no cw.exe/runtime dependency.
    add_executable(cw_trainer_runtime WIN32
        portable_win/TrainerRuntime_NoCRT.cpp
        portable_win/StandardCRTEntry.cpp)
    set_target_properties(cw_trainer_runtime PROPERTIES OUTPUT_NAME "trainer-runtime-template")
    cw_add_version_resource(cw_trainer_runtime "trainer-runtime-template.exe" "Cheat Wizard Trainer Runtime" "trainer-runtime-template")
    cw_harden_windows_target(cw_trainer_runtime)
    target_compile_features(cw_trainer_runtime PRIVATE cxx_std_20)
    target_compile_definitions(cw_trainer_runtime PRIVATE CW_USE_STANDARD_CRT=1 CW_CRT_ENTRY_TRAINER=1)
    set_property(TARGET cw_trainer_runtime PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_link_libraries(cw_trainer_runtime PRIVATE kernel32 user32 gdi32)
    if(MSVC)
        target_compile_options(cw_trainer_runtime PRIVATE /W4 /permissive- /EHsc /GS)
    endif()

    set(TRAINER_BLOB_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
    set(TRAINER_BLOB_HPP "${TRAINER_BLOB_DIR}/TrainerRuntimeBlob.hpp")
    add_custom_command(
        OUTPUT "${TRAINER_BLOB_HPP}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${TRAINER_BLOB_DIR}"
        COMMAND ${CMAKE_COMMAND} -DINPUT=$<TARGET_FILE:cw_trainer_runtime> -DOUTPUT=${TRAINER_BLOB_HPP} -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/EmbedBinary.cmake"
        DEPENDS cw_trainer_runtime "${CMAKE_CURRENT_SOURCE_DIR}/cmake/EmbedBinary.cmake"
        VERBATIM)
    add_executable(cw_trainer_builder
        portable_win/TrainerBuilder_NoCRT.cpp
        portable_win/StandardCRTEntry.cpp
        "${TRAINER_BLOB_HPP}")
    set_target_properties(cw_trainer_builder PROPERTIES OUTPUT_NAME "cw-trainer-builder")
    cw_add_version_resource(cw_trainer_builder "cw-trainer-builder.exe" "Cheat Wizard Trainer Builder" "cw-trainer-builder")
    cw_harden_windows_target(cw_trainer_builder)
    target_include_directories(cw_trainer_builder PRIVATE "${TRAINER_BLOB_DIR}")
    target_compile_features(cw_trainer_builder PRIVATE cxx_std_20)
    target_compile_definitions(cw_trainer_builder PRIVATE CW_USE_STANDARD_CRT=1 CW_CRT_ENTRY_BUILDER=1)
    set_property(TARGET cw_trainer_builder PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_link_libraries(cw_trainer_builder PRIVATE kernel32)
    if(MSVC)
        target_compile_options(cw_trainer_builder PRIVATE /W4 /permissive- /EHsc /GS)
    endif()
else()
    message(STATUS "Non-Windows host: building portable/core + mock Win32 scanner tests. Cheat Wizard executable uses real Win32 APIs only on Windows.")
endif()

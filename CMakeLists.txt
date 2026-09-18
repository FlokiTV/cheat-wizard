cmake_minimum_required(VERSION 3.20)
project(CheatWizard VERSION 1.7.3 LANGUAGES CXX)

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

if(MSVC)
    target_compile_options(cw_core PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(cw_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(BUILD_TESTING)
    add_executable(cw_core_tests tests/CoreTests.cpp)
    if(WIN32)
        target_sources(cw_core_tests PRIVATE src/MemoryScanner.cpp)
        target_compile_definitions(cw_core_tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    endif()
    target_link_libraries(cw_core_tests PRIVATE cw_core)
    target_compile_features(cw_core_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(cw_core_tests PRIVATE /W4 /permissive- /EHsc)
    else()
        target_compile_options(cw_core_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME cw_core_tests COMMAND cw_core_tests)

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

        add_executable(cw_mock_pointer_tests
            tests/MockPointerScannerTests.cpp
            src/PointerScanner.cpp
        )
        target_link_libraries(cw_mock_pointer_tests PRIVATE cw_core)
        target_include_directories(cw_mock_pointer_tests PRIVATE tests/win32_stubs include)
        target_compile_features(cw_mock_pointer_tests PRIVATE cxx_std_20)
        target_compile_options(cw_mock_pointer_tests PRIVATE -Wall -Wextra -Wpedantic)
        add_test(NAME cw_mock_pointer_tests COMMAND cw_mock_pointer_tests)
    endif()
endif()

if(WIN32)
    enable_language(RC)

    function(cw_add_version_resource target original_filename file_description internal_name)
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

    add_executable(cw_cli
        src/main.cpp
        src/ProcessManager.cpp
        src/MemoryScanner.cpp
        src/AobScanner.cpp
        src/MemoryWriter.cpp
        src/FreezeManager.cpp
        src/PointerScanner.cpp
    )
    set_target_properties(cw_cli PROPERTIES OUTPUT_NAME "cw")
    cw_add_version_resource(cw_cli "cw.exe" "Cheat Wizard Command Line" "cw")
    cw_harden_windows_target(cw_cli)
    target_link_libraries(cw_cli PRIVATE cw_core)
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
        portable_win/StandardCRTEntry.cpp)
    set_target_properties(cw_gui PROPERTIES OUTPUT_NAME "cw-gui")
    cw_add_version_resource(cw_gui "cw-gui.exe" "Cheat Wizard" "cw-gui")
    cw_harden_windows_target(cw_gui)
    target_compile_features(cw_gui PRIVATE cxx_std_20)
    target_compile_definitions(cw_gui PRIVATE CW_USE_STANDARD_CRT=1 CW_CRT_ENTRY_GUI=1)
    set_property(TARGET cw_gui PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_link_libraries(cw_gui PRIVATE kernel32 user32 gdi32 msimg32)
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

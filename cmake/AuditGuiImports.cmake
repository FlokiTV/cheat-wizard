if(NOT DEFINED INPUT OR NOT EXISTS "${INPUT}")
    message(FATAL_ERROR "GUI import audit input is missing: ${INPUT}")
endif()

file(READ "${INPUT}" imports)

set(forbidden_imports
    OpenProcess
    ReadProcessMemory
    WriteProcessMemory
    VirtualQueryEx
    CreateToolhelp32Snapshot
    Process32First
    Process32Next
    Module32FirstW
    Module32NextW
    VirtualProtectEx
    CreateRemoteThread)

set(found "")
foreach(symbol IN LISTS forbidden_imports)
    string(FIND "${imports}" "${symbol}" position)
    if(NOT position EQUAL -1)
        list(APPEND found "${symbol}")
    endif()
endforeach()

if(found)
    list(JOIN found ", " found_text)
    message(FATAL_ERROR "cw-gui.exe contains forbidden live-process imports: ${found_text}")
endif()

message(STATUS "GUI import audit PASS: no live-process memory/toolhelp imports")

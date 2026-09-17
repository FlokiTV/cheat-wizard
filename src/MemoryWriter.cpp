#include "cw/MemoryWriter.hpp"

namespace cw {

WriteResult writeValue(HANDLE process, std::uintptr_t address, const Value& value) {
    WriteResult result{};
    if (!process) {
        result.error = ERROR_INVALID_HANDLE;
        return result;
    }

    result = std::visit([&](const auto& typedValue) -> WriteResult {
        WriteResult out{};
        SIZE_T bytesWritten = 0;
        const BOOL ok = WriteProcessMemory(
            process,
            reinterpret_cast<LPVOID>(address),
            &typedValue,
            sizeof(typedValue),
            &bytesWritten);
        out.ok = ok && bytesWritten == sizeof(typedValue);
        out.bytesWritten = bytesWritten;
        out.error = out.ok ? ERROR_SUCCESS : GetLastError();
        return out;
    }, value);

    return result;
}

} // namespace cw

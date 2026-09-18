#include "cw/ProcessManager.hpp"

#include <sstream>

namespace cw {

std::string win32ErrorMessage(DWORD errorCode) {
    LPSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD size = FormatMessageA(
        flags, nullptr, errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buffer), 0, nullptr);

    if (size == 0 || !buffer) {
        std::ostringstream out;
        out << "Win32 error " << errorCode;
        return out.str();
    }

    std::string message(buffer, size);
    LocalFree(buffer);
    while (!message.empty() && (message.back() == '\r' || message.back() == '\n')) {
        message.pop_back();
    }
    return message;
}

} // namespace cw

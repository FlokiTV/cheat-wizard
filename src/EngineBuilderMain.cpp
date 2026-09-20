#include <Windows.h>
#include <bcrypt.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;

namespace {

constexpr int kPayloadResourceId = 201;
constexpr wchar_t kBuilderVersion[] = L"1.7.3";
constexpr wchar_t kEngineFilename[] = L"cw-engine.exe";
constexpr wchar_t kManifestFilename[] = L"cw-engine.build.json";

const std::array<const wchar_t*, 21> kSourceNames{{
    L"Value", L"AobPattern", L"AobPersistence", L"ScanPersistence",
    L"RelativeAddress", L"InstructionDecode", L"PointerAlgorithms",
    L"PointerPersistence", L"PointerProfile", L"PointerMap", L"Win32Error",
    L"EngineSession", L"ProcessManager", L"MemoryScanner", L"AobScanner",
    L"MemoryWriter", L"FreezeManager", L"PointerScanner",
    L"EngineProtocol", L"EnginePipe", L"EngineMain"
}};

std::wstring quoteArgument(std::wstring_view argument) {
    if (argument.empty()) return L"\"\"";
    bool needsQuotes = false;
    for (wchar_t c : argument) {
        if (c == L' ' || c == L'\t' || c == L'"') {
            needsQuotes = true;
            break;
        }
    }
    if (!needsQuotes) return std::wstring(argument);

    std::wstring out;
    out.push_back(L'"');
    std::size_t slashes = 0;
    for (wchar_t c : argument) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        if (c == L'"') {
            out.append(slashes * 2 + 1, L'\\');
            out.push_back(L'"');
            slashes = 0;
            continue;
        }
        out.append(slashes, L'\\');
        slashes = 0;
        out.push_back(c);
    }
    out.append(slashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

std::wstring buildCommandLine(const fs::path& executable, const std::vector<std::wstring>& args) {
    std::wstring command = quoteArgument(executable.wstring());
    for (const auto& arg : args) {
        command.push_back(L' ');
        command += quoteArgument(arg);
    }
    return command;
}

bool runProcess(
    const fs::path& executable,
    const std::vector<std::wstring>& args,
    const fs::path& workingDirectory,
    DWORD& exitCode,
    std::string* capturedOutput = nullptr)
{
    std::wstring command = buildCommandLine(executable, args);
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    HANDLE captureHandle = INVALID_HANDLE_VALUE;
    fs::path capturePath;
    BOOL inheritHandles = FALSE;

    if (capturedOutput) {
        capturePath = workingDirectory / L"process-output.txt";
        SECURITY_ATTRIBUTES attributes{};
        attributes.nLength = sizeof(attributes);
        attributes.bInheritHandle = TRUE;
        captureHandle = CreateFileW(
            capturePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (captureHandle == INVALID_HANDLE_VALUE) return false;
        startup.dwFlags |= STARTF_USESTDHANDLES;
        startup.hStdOutput = captureHandle;
        startup.hStdError = captureHandle;
        startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        inheritHandles = TRUE;
    }

    const BOOL created = CreateProcessW(
        executable.c_str(),
        mutableCommand.data(),
        nullptr,
        nullptr,
        inheritHandles,
        0,
        nullptr,
        workingDirectory.c_str(),
        &startup,
        &process);

    if (!created) {
        if (captureHandle != INVALID_HANDLE_VALUE) CloseHandle(captureHandle);
        return false;
    }

    CloseHandle(process.hThread);
    const DWORD wait = WaitForSingleObject(process.hProcess, INFINITE);
    if (wait != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &exitCode)) {
        CloseHandle(process.hProcess);
        if (captureHandle != INVALID_HANDLE_VALUE) CloseHandle(captureHandle);
        return false;
    }
    CloseHandle(process.hProcess);

    if (captureHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(captureHandle);
        std::ifstream input(capturePath, std::ios::binary);
        std::ostringstream buffer;
        buffer << input.rdbuf();
        *capturedOutput = buffer.str();
        std::error_code ec;
        fs::remove(capturePath, ec);
    }
    return true;
}

fs::path executableDirectory() {
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) {
        throw std::runtime_error("Could not determine builder executable path");
    }
    buffer.resize(length);
    return fs::path(buffer).parent_path();
}

fs::path temporaryWorkspace() {
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
    if (length == 0 || length >= buffer.size()) {
        throw std::runtime_error("Could not determine temporary directory");
    }
    buffer.resize(length);
    std::wstringstream name;
    name << L"CheatWizard.EngineBuild." << GetCurrentProcessId() << L"." << GetTickCount64();
    return fs::path(buffer) / name.str();
}

void writePayloadResource(const fs::path& destination) {
    HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(kPayloadResourceId), RT_RCDATA);
    if (!resource) throw std::runtime_error("Embedded engine-builder payload was not found");
    HGLOBAL loaded = LoadResource(nullptr, resource);
    if (!loaded) throw std::runtime_error("Could not load embedded engine-builder payload");
    const DWORD size = SizeofResource(nullptr, resource);
    const void* data = LockResource(loaded);
    if (!data || size == 0) throw std::runtime_error("Embedded engine-builder payload is empty");

    std::ofstream output(destination, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Could not create temporary payload archive");
    output.write(static_cast<const char*>(data), size);
    if (!output) throw std::runtime_error("Could not write temporary payload archive");
}

std::map<std::string, std::string> readMetadata(const fs::path& path) {
    std::ifstream input(path);
    if (!input) throw std::runtime_error("BUILD-METADATA.txt is missing from payload");
    std::map<std::string, std::string> values;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto equal = line.find('=');
        if (equal == std::string::npos) continue;
        values[line.substr(0, equal)] = line.substr(equal + 1);
    }
    const std::array<const char*, 8> required{{
        "schema", "engineVersion", "protocolMajor", "protocolMinor",
        "architecture", "sourceRevision", "sourceDigest", "toolchain"
    }};
    for (const char* key : required) {
        if (!values.contains(key) || values[key].empty()) {
            throw std::runtime_error(std::string("Payload metadata missing key: ") + key);
        }
    }
    if (values["schema"] != "1" || values["architecture"] != "x64") {
        throw std::runtime_error("Payload metadata is incompatible with this builder");
    }
    return values;
}

bool validatePe(const fs::path& path, std::string& error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "Could not open generated engine";
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    input.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!input || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) {
        error = "Generated file is not a valid PE/DOS image";
        return false;
    }

    input.seekg(dos.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS64 nt{};
    input.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (!input ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI) {
        error = "Generated engine is not a Windows x64 console PE";
        return false;
    }

    const WORD required =
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    if ((nt.OptionalHeader.DllCharacteristics & required) != required) {
        error = "Generated engine is missing required ASLR/NX/HighEntropyVA PE flags";
        return false;
    }
    return true;
}

std::string sha256File(const fs::path& path) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD hashSize = 0;
    DWORD resultSize = 0;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider(SHA256) failed");
    }

    auto closeAlgorithm = [&] {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    };

    if (BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
            sizeof(objectSize), &resultSize, 0) < 0 ||
        BCryptGetProperty(
            algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashSize),
            sizeof(hashSize), &resultSize, 0) < 0) {
        closeAlgorithm();
        throw std::runtime_error("Could not query SHA-256 provider");
    }

    std::vector<UCHAR> object(objectSize);
    std::vector<UCHAR> digest(hashSize);
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) < 0) {
        closeAlgorithm();
        throw std::runtime_error("BCryptCreateHash failed");
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        closeAlgorithm();
        throw std::runtime_error("Could not open generated engine for hashing");
    }
    std::array<char, 64 * 1024> buffer{};
    while (input) {
        input.read(buffer.data(), buffer.size());
        const auto count = input.gcount();
        if (count > 0 &&
            BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(count), 0) < 0) {
            closeAlgorithm();
            throw std::runtime_error("BCryptHashData failed");
        }
    }
    if (!input.eof()) {
        closeAlgorithm();
        throw std::runtime_error("Could not read generated engine for hashing");
    }

    if (BCryptFinishHash(hash, digest.data(), hashSize, 0) < 0) {
        closeAlgorithm();
        throw std::runtime_error("BCryptFinishHash failed");
    }
    closeAlgorithm();

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (UCHAR byte : digest) output << std::setw(2) << static_cast<unsigned>(byte);
    return output.str();
}

std::string jsonEscape(std::string_view value) {
    std::string out;
    out.reserve(value.size() + 16);
    for (unsigned char c : value) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    const char hex[] = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(hex[(c >> 4) & 0xf]);
                    out.push_back(hex[c & 0xf]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

void writeBuildManifest(
    const fs::path& path,
    const std::map<std::string, std::string>& metadata,
    const std::string& engineHash)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Could not create engine build manifest");
    output
        << "{\n"
        << "  \"schema\": 1,\n"
        << "  \"engineVersion\": \"" << jsonEscape(metadata.at("engineVersion")) << "\",\n"
        << "  \"protocolMajor\": " << metadata.at("protocolMajor") << ",\n"
        << "  \"protocolMinor\": " << metadata.at("protocolMinor") << ",\n"
        << "  \"architecture\": \"x64\",\n"
        << "  \"sourceRevision\": \"" << jsonEscape(metadata.at("sourceRevision")) << "\",\n"
        << "  \"sourceDigest\": \"" << jsonEscape(metadata.at("sourceDigest")) << "\",\n"
        << "  \"toolchain\": \"" << jsonEscape(metadata.at("toolchain")) << "\",\n"
        << "  \"engineSha256\": \"" << engineHash << "\",\n"
        << "  \"builtLocally\": true\n"
        << "}\n";
    if (!output) throw std::runtime_error("Could not write engine build manifest");
}

void atomicInstall(const fs::path& candidate, const fs::path& manifest, const fs::path& outputDirectory) {
    fs::create_directories(outputDirectory);
    const fs::path finalEngine = outputDirectory / kEngineFilename;
    const fs::path finalManifest = outputDirectory / kManifestFilename;
    const fs::path stagedEngine = outputDirectory / L"cw-engine.new.exe";
    const fs::path stagedManifest = outputDirectory / L"cw-engine.build.new.json";
    const fs::path backupEngine = outputDirectory / L"cw-engine.previous.exe";
    const fs::path backupManifest = outputDirectory / L"cw-engine.build.previous.json";

    std::error_code ec;
    fs::remove(stagedEngine, ec);
    fs::remove(stagedManifest, ec);
    fs::remove(backupEngine, ec);
    fs::remove(backupManifest, ec);

    fs::copy_file(candidate, stagedEngine, fs::copy_options::overwrite_existing);
    fs::copy_file(manifest, stagedManifest, fs::copy_options::overwrite_existing);

    bool engineBackedUp = false;
    bool manifestBackedUp = false;
    auto moveReplace = [](const fs::path& from, const fs::path& to) {
        return MoveFileExW(
            from.c_str(), to.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
    };

    if (fs::exists(finalEngine)) {
        if (!moveReplace(finalEngine, backupEngine)) {
            throw std::runtime_error("Could not replace cw-engine.exe. Close Cheat Wizard/engine and retry.");
        }
        engineBackedUp = true;
    }
    if (fs::exists(finalManifest)) {
        if (!moveReplace(finalManifest, backupManifest)) {
            if (engineBackedUp) moveReplace(backupEngine, finalEngine);
            throw std::runtime_error("Could not back up existing cw-engine.build.json");
        }
        manifestBackedUp = true;
    }

    if (!moveReplace(stagedEngine, finalEngine)) {
        if (manifestBackedUp) moveReplace(backupManifest, finalManifest);
        if (engineBackedUp) moveReplace(backupEngine, finalEngine);
        throw std::runtime_error("Could not install new cw-engine.exe");
    }
    if (!moveReplace(stagedManifest, finalManifest)) {
        fs::remove(finalEngine, ec);
        if (manifestBackedUp) moveReplace(backupManifest, finalManifest);
        if (engineBackedUp) moveReplace(backupEngine, finalEngine);
        throw std::runtime_error("Could not install cw-engine.build.json; previous engine restored");
    }

    fs::remove(backupEngine, ec);
    fs::remove(backupManifest, ec);
}

std::vector<std::wstring> compileArguments(
    const fs::path& source,
    const fs::path& includeDirectory,
    const fs::path& object)
{
    return {
        L"-std=c++20", L"-O2", L"-DNDEBUG",
        L"-DUNICODE", L"-D_UNICODE", L"-DWIN32_LEAN_AND_MEAN", L"-DNOMINMAX",
        L"-I" + includeDirectory.wstring(),
        L"-fstack-protector-strong", L"-fcf-protection=full",
        L"-c", source.wstring(), L"-o", object.wstring()
    };
}

int buildEngine(const fs::path& outputDirectory) {
    const fs::path workspace = temporaryWorkspace();
    try {
        fs::create_directories(workspace);
        const fs::path payloadZip = workspace / L"payload.zip";

        std::cout << "Preparing embedded source/toolchain...\n";
        writePayloadResource(payloadZip);

        std::wstring systemDirectory(MAX_PATH, L'\0');
        const UINT systemLength = GetSystemDirectoryW(systemDirectory.data(), static_cast<UINT>(systemDirectory.size()));
        if (systemLength == 0 || systemLength >= systemDirectory.size()) {
            throw std::runtime_error("Could not locate Windows System32");
        }
        systemDirectory.resize(systemLength);
        const fs::path tar = fs::path(systemDirectory) / L"tar.exe";
        if (!fs::exists(tar)) {
            throw std::runtime_error("Windows tar.exe is required to unpack the embedded build payload");
        }

        DWORD exitCode = 0;
        if (!runProcess(tar, {L"-xf", payloadZip.wstring(), L"-C", workspace.wstring()}, workspace, exitCode) ||
            exitCode != 0) {
            throw std::runtime_error("Could not unpack embedded engine build payload");
        }
        fs::remove(payloadZip);

        const auto metadata = readMetadata(workspace / L"BUILD-METADATA.txt");
        const fs::path toolchain = workspace / L"toolchain";
        const fs::path sourceRoot = workspace / L"source";
        const fs::path compiler = toolchain / L"bin" / L"x86_64-w64-mingw32-clang++.exe";
        const fs::path windres = toolchain / L"bin" / L"llvm-windres.exe";
        const fs::path objectDirectory = workspace / L"obj";
        fs::create_directories(objectDirectory);

        std::vector<fs::path> objects;
        objects.reserve(kSourceNames.size() + 1);

        std::cout << "Compiling engine locally...\n";
        std::size_t index = 0;
        for (const wchar_t* name : kSourceNames) {
            ++index;
            const fs::path source = sourceRoot / L"src" / (std::wstring(name) + L".cpp");
            const fs::path object = objectDirectory / (std::wstring(name) + L".o");
            std::wcout << L"  [" << index << L"/" << kSourceNames.size() << L"] " << name << L".cpp\n";
            if (!runProcess(
                    compiler,
                    compileArguments(source, sourceRoot / L"include", object),
                    workspace,
                    exitCode) ||
                exitCode != 0) {
                throw std::runtime_error("Engine source compilation failed");
            }
            objects.push_back(object);
        }

        std::cout << "Compiling VERSIONINFO resource...\n";
        const fs::path resourceObject = objectDirectory / L"engine-version.o";
        if (!runProcess(
                windres,
                {L"-i", (sourceRoot / L"engine-version.rc").wstring(),
                 L"-o", resourceObject.wstring(), L"-O", L"coff"},
                workspace,
                exitCode) ||
            exitCode != 0) {
            throw std::runtime_error("Engine VERSIONINFO resource compilation failed");
        }
        objects.push_back(resourceObject);

        std::cout << "Linking cw-engine.exe...\n";
        std::vector<std::wstring> linkArgs{
            L"-municode", L"-static",
            L"-Wl,--dynamicbase,--high-entropy-va,--nxcompat"
        };
        for (const auto& object : objects) linkArgs.push_back(object.wstring());
        linkArgs.push_back(L"-ladvapi32");
        const fs::path candidate = workspace / L"cw-engine.candidate.exe";
        linkArgs.push_back(L"-o");
        linkArgs.push_back(candidate.wstring());

        if (!runProcess(compiler, linkArgs, workspace, exitCode) || exitCode != 0) {
            throw std::runtime_error("Engine link failed");
        }

        std::cout << "Validating generated engine...\n";
        std::string peError;
        if (!validatePe(candidate, peError)) throw std::runtime_error(peError);

        std::string versionOutput;
        if (!runProcess(candidate, {L"--version"}, workspace, exitCode, &versionOutput) ||
            exitCode != 0 ||
            versionOutput.find("protocol 1.1") == std::string::npos) {
            throw std::runtime_error("Generated engine failed protocol/version self-check");
        }

        const std::string engineHash = sha256File(candidate);
        const fs::path manifest = workspace / kManifestFilename;
        writeBuildManifest(manifest, metadata, engineHash);

        std::cout << "Installing engine atomically...\n";
        atomicInstall(candidate, manifest, outputDirectory);

        std::cout << "Engine ready.\n";
        std::cout << "  Output: " << (outputDirectory / kEngineFilename).string() << "\n";
        std::cout << "  SHA-256: " << engineHash << "\n";
        std::cout << "  Source revision: " << metadata.at("sourceRevision") << "\n";
        std::cout << "  Toolchain: " << metadata.at("toolchain") << "\n";

        std::error_code cleanupError;
        fs::remove_all(workspace, cleanupError);
        return 0;
    }
    catch (...) {
        std::error_code cleanupError;
        fs::remove_all(workspace, cleanupError);
        throw;
    }
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        fs::path outputDirectory = executableDirectory();
        for (int i = 1; i < argc; ++i) {
            const std::wstring_view arg(argv[i]);
            if (arg == L"--version") {
                std::wcout << L"Cheat Wizard Engine Builder v" << kBuilderVersion << L"\n";
                return 0;
            }
            if (arg == L"--output-dir" && i + 1 < argc) {
                outputDirectory = fs::absolute(argv[++i]);
                continue;
            }
            std::wcerr << L"Usage: cw-engine-builder.exe [--output-dir <directory>] [--version]\n";
            return 1;
        }
        return buildEngine(outputDirectory);
    }
    catch (const std::exception& error) {
        std::cerr << "Engine build failed: " << error.what() << "\n";
        return 2;
    }
}

#include <Windows.h>
#include <CommCtrl.h>
#include <bcrypt.h>
#include <shellapi.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")

namespace fs = std::filesystem;

namespace {

constexpr int kPayloadResourceId = 301;
constexpr int kAppIconResourceId = 101;
constexpr wchar_t kBuilderVersion[] = L"1.7.3";
constexpr UINT WM_CW_STATUS = WM_APP + 41;
constexpr UINT WM_CW_DONE = WM_APP + 42;
constexpr int kButtonId = 1001;
constexpr int kProgressId = 1002;
constexpr UINT_PTR kAutoCloseTimerId = 1;

using StatusCallback = std::function<void(const std::wstring&)>;

struct SourceSpec {
    fs::path relative;
    std::wstring objectName;
    std::vector<std::wstring> defines;
};

std::wstring utf8ToWide(std::string_view text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring out(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size);
    return out;
}

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
            capturePath.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY,
            nullptr);
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
        CREATE_NO_WINDOW,
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

fs::path executablePath() {
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) {
        throw std::runtime_error("Could not determine builder executable path");
    }
    buffer.resize(length);
    return fs::path(buffer);
}

fs::path executableDirectory() {
    return executablePath().parent_path();
}

fs::path temporaryWorkspace() {
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
    if (length == 0 || length >= buffer.size()) {
        throw std::runtime_error("Could not determine temporary directory");
    }
    buffer.resize(length);
    std::wstringstream name;
    name << L"CheatWizard.ProductBuild." << GetCurrentProcessId() << L"." << GetTickCount64();
    return fs::path(buffer) / name.str();
}

void setStatus(const StatusCallback& callback, const std::wstring& value) {
    if (callback) callback(value);
}

void writePayloadResource(const fs::path& destination) {
    HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(kPayloadResourceId), RT_RCDATA);
    if (!resource) throw std::runtime_error("Embedded product-builder payload was not found");
    HGLOBAL loaded = LoadResource(nullptr, resource);
    if (!loaded) throw std::runtime_error("Could not load embedded product-builder payload");
    const DWORD size = SizeofResource(nullptr, resource);
    const void* data = LockResource(loaded);
    if (!data || size == 0) throw std::runtime_error("Embedded product-builder payload is empty");

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

    const std::array<const char*, 9> required{{
        "schema", "productVersion", "engineVersion", "protocolMajor", "protocolMinor",
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

std::string sha256File(const fs::path& path) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD hashSize = 0;
    DWORD resultSize = 0;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider(SHA256) failed");
    }
    auto cleanup = [&] {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    };

    if (BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
            sizeof(objectSize), &resultSize, 0) < 0 ||
        BCryptGetProperty(
            algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashSize),
            sizeof(hashSize), &resultSize, 0) < 0) {
        cleanup();
        throw std::runtime_error("Could not query SHA-256 provider");
    }

    std::vector<UCHAR> object(objectSize);
    std::vector<UCHAR> digest(hashSize);
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) < 0) {
        cleanup();
        throw std::runtime_error("BCryptCreateHash failed");
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        cleanup();
        throw std::runtime_error("Could not open file for hashing");
    }
    std::array<char, 64 * 1024> buffer{};
    while (input) {
        input.read(buffer.data(), buffer.size());
        const auto count = input.gcount();
        if (count > 0 &&
            BCryptHashData(
                hash,
                reinterpret_cast<PUCHAR>(buffer.data()),
                static_cast<ULONG>(count),
                0) < 0) {
            cleanup();
            throw std::runtime_error("BCryptHashData failed");
        }
    }
    if (!input.eof()) {
        cleanup();
        throw std::runtime_error("Could not read file for hashing");
    }
    if (BCryptFinishHash(hash, digest.data(), hashSize, 0) < 0) {
        cleanup();
        throw std::runtime_error("BCryptFinishHash failed");
    }
    cleanup();

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (UCHAR byte : digest) output << std::setw(2) << static_cast<unsigned>(byte);
    return output.str();
}

std::string jsonEscape(std::string_view value) {
    std::string out;
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

bool validatePe(const fs::path& path, WORD subsystem, std::string& error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "Could not open generated PE";
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
        nt.OptionalHeader.Subsystem != subsystem) {
        error = "Generated file has unexpected PE architecture/subsystem";
        return false;
    }
    const WORD required =
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    if ((nt.OptionalHeader.DllCharacteristics & required) != required) {
        error = "Generated file is missing required ASLR/NX/HighEntropyVA flags";
        return false;
    }
    return true;
}

std::vector<std::wstring> compileArguments(
    const fs::path& source,
    const std::vector<fs::path>& includes,
    const std::vector<std::wstring>& defines,
    const fs::path& object)
{
    std::vector<std::wstring> args{
        L"-std=c++20", L"-O2", L"-DNDEBUG",
        L"-DUNICODE", L"-D_UNICODE", L"-DWIN32_LEAN_AND_MEAN", L"-DNOMINMAX",
        L"-fstack-protector-strong", L"-fcf-protection=full"
    };
    for (const auto& define : defines) args.push_back(L"-D" + define);
    for (const auto& include : includes) args.push_back(L"-I" + include.wstring());
    args.push_back(L"-c");
    args.push_back(source.wstring());
    args.push_back(L"-o");
    args.push_back(object.wstring());
    return args;
}

fs::path compileSource(
    const fs::path& compiler,
    const fs::path& sourceRoot,
    const fs::path& objectDirectory,
    const SourceSpec& spec,
    const std::vector<fs::path>& extraIncludes = {})
{
    const fs::path source = sourceRoot / spec.relative;
    const fs::path object = objectDirectory / spec.objectName;
    std::vector<fs::path> includes{
        sourceRoot / L"include",
        sourceRoot / L"portable_win"
    };
    includes.insert(includes.end(), extraIncludes.begin(), extraIncludes.end());

    DWORD exitCode = 0;
    std::string output;
    if (!runProcess(
            compiler,
            compileArguments(source, includes, spec.defines, object),
            objectDirectory,
            exitCode,
            &output) ||
        exitCode != 0) {
        throw std::runtime_error(
            "Compilation failed for " + spec.relative.string() + ":\n" + output);
    }
    return object;
}

fs::path compileResource(
    const fs::path& windres,
    const fs::path& source,
    const fs::path& object,
    const fs::path& workingDirectory)
{
    DWORD exitCode = 0;
    std::string output;
    if (!runProcess(
            windres,
            {L"-i", source.wstring(), L"-o", object.wstring(), L"-O", L"coff"},
            workingDirectory,
            exitCode,
            &output) ||
        exitCode != 0) {
        throw std::runtime_error("Resource compilation failed for " + source.string() + ":\n" + output);
    }
    return object;
}

void linkExecutable(
    const fs::path& compiler,
    const std::vector<fs::path>& objects,
    const std::vector<std::wstring>& libraries,
    const fs::path& output,
    bool windowsSubsystem,
    bool unicodeConsole,
    const fs::path& workingDirectory)
{
    std::vector<std::wstring> args;
    if (windowsSubsystem) args.push_back(L"-mwindows");
    if (unicodeConsole) args.push_back(L"-municode");
    args.push_back(L"-static");
    args.push_back(L"-Wl,--dynamicbase,--high-entropy-va,--nxcompat");
    for (const auto& object : objects) args.push_back(object.wstring());
    for (const auto& library : libraries) args.push_back(library);
    args.push_back(L"-o");
    args.push_back(output.wstring());

    DWORD exitCode = 0;
    std::string buildOutput;
    if (!runProcess(compiler, args, workingDirectory, exitCode, &buildOutput) || exitCode != 0) {
        throw std::runtime_error("Link failed for " + output.filename().string() + ":\n" + buildOutput);
    }
}

void writeTrainerBlobHeader(const fs::path& runtime, const fs::path& header) {
    std::ifstream input(runtime, std::ios::binary);
    if (!input) throw std::runtime_error("Could not read trainer runtime template");
    std::vector<unsigned char> bytes(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());

    std::ofstream output(header, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Could not create TrainerRuntimeBlob.hpp");

    output << "#pragma once\nstatic const unsigned char g_trainer_runtime_bytes[] = {\n";
    output << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if ((i % 16) == 0) output << "  ";
        output << "0x" << std::setw(2) << static_cast<unsigned>(bytes[i]) << ",";
        if ((i % 16) == 15) output << "\n";
    }
    if ((bytes.size() % 16) != 0) output << "\n";
    output << "};\n"
           << "static const unsigned long long g_trainer_runtime_size = "
           << "sizeof(g_trainer_runtime_bytes);\n";
    if (!output) throw std::runtime_error("Could not write TrainerRuntimeBlob.hpp");
}

void writeEngineManifest(
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
}

void writeProductManifest(
    const fs::path& path,
    const std::map<std::string, std::string>& metadata,
    const std::map<std::string, std::string>& hashes)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Could not create product build manifest");
    output
        << "{\n"
        << "  \"schema\": 1,\n"
        << "  \"productVersion\": \"" << jsonEscape(metadata.at("productVersion")) << "\",\n"
        << "  \"architecture\": \"x64\",\n"
        << "  \"sourceRevision\": \"" << jsonEscape(metadata.at("sourceRevision")) << "\",\n"
        << "  \"sourceDigest\": \"" << jsonEscape(metadata.at("sourceDigest")) << "\",\n"
        << "  \"toolchain\": \"" << jsonEscape(metadata.at("toolchain")) << "\",\n"
        << "  \"builtLocally\": true,\n"
        << "  \"files\": {\n";
    std::size_t index = 0;
    for (const auto& [name, hash] : hashes) {
        output << "    \"" << jsonEscape(name) << "\": \"" << hash << "\"";
        if (++index != hashes.size()) output << ",";
        output << "\n";
    }
    output << "  }\n}\n";
}

void copyTreeFile(const fs::path& source, const fs::path& destination) {
    fs::create_directories(destination.parent_path());
    fs::copy_file(source, destination, fs::copy_options::overwrite_existing);
}

void atomicInstallDirectory(const fs::path& product, const fs::path& outputDirectory) {
    const fs::path parent = outputDirectory.parent_path();
    if (parent.empty()) throw std::runtime_error("Output directory must have a parent directory");
    fs::create_directories(parent);

    const fs::path staged = parent / (outputDirectory.filename().wstring() + L".new");
    const fs::path backup = parent / (outputDirectory.filename().wstring() + L".previous");

    std::error_code ec;
    fs::remove_all(staged, ec);
    fs::remove_all(backup, ec);
    fs::copy(product, staged, fs::copy_options::recursive | fs::copy_options::overwrite_existing);

    auto moveReplace = [](const fs::path& from, const fs::path& to) {
        return MoveFileExW(
            from.c_str(),
            to.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
    };

    bool backedUp = false;
    if (fs::exists(outputDirectory)) {
        if (!moveReplace(outputDirectory, backup)) {
            fs::remove_all(staged, ec);
            throw std::runtime_error("Could not replace existing Cheat-Wizard folder. Close running files and retry.");
        }
        backedUp = true;
    }

    if (!moveReplace(staged, outputDirectory)) {
        if (backedUp) moveReplace(backup, outputDirectory);
        fs::remove_all(staged, ec);
        throw std::runtime_error("Could not install the newly built Cheat-Wizard folder");
    }

    fs::remove_all(backup, ec);
}

int buildProduct(const fs::path& outputDirectory, const StatusCallback& status) {
    const fs::path workspace = temporaryWorkspace();
    try {
        fs::create_directories(workspace);
        const fs::path payloadZip = workspace / L"product-payload.zip";

        setStatus(status, L"Preparing embedded source and toolchain...");
        writePayloadResource(payloadZip);

        std::wstring systemDirectory(MAX_PATH, L'\0');
        const UINT systemLength = GetSystemDirectoryW(systemDirectory.data(), static_cast<UINT>(systemDirectory.size()));
        if (systemLength == 0 || systemLength >= systemDirectory.size()) {
            throw std::runtime_error("Could not locate Windows System32");
        }
        systemDirectory.resize(systemLength);
        const fs::path tar = fs::path(systemDirectory) / L"tar.exe";
        if (!fs::exists(tar)) throw std::runtime_error("Windows tar.exe is required to unpack the build payload");

        DWORD exitCode = 0;
        std::string extractOutput;
        if (!runProcess(
                tar,
                {L"-xf", payloadZip.wstring(), L"-C", workspace.wstring()},
                workspace,
                exitCode,
                &extractOutput) ||
            exitCode != 0) {
            throw std::runtime_error("Could not unpack embedded product payload:\n" + extractOutput);
        }

        const auto metadata = readMetadata(workspace / L"BUILD-METADATA.txt");
        const fs::path toolchain = workspace / L"toolchain";
        const fs::path sourceRoot = workspace / L"source";
        const fs::path compiler = toolchain / L"bin" / L"x86_64-w64-mingw32-clang++.exe";
        const fs::path windres = toolchain / L"bin" / L"llvm-windres.exe";
        if (!fs::exists(compiler) || !fs::exists(windres)) {
            throw std::runtime_error("Embedded compiler toolchain is incomplete");
        }

        const fs::path objectDirectory = workspace / L"obj";
        const fs::path generatedDirectory = workspace / L"generated";
        const fs::path productDirectory = workspace / L"product";
        fs::create_directories(objectDirectory);
        fs::create_directories(generatedDirectory);
        fs::create_directories(productDirectory);

        const std::vector<std::wstring> coreNames{
            L"Value", L"AobPattern", L"AobPersistence", L"ScanPersistence",
            L"RelativeAddress", L"InstructionDecode", L"PointerAlgorithms",
            L"PointerPersistence", L"PointerProfile", L"PointerMap", L"Win32Error"
        };
        const std::vector<std::wstring> engineCoreNames{
            L"EngineSession", L"ProcessManager", L"MemoryScanner", L"AobScanner",
            L"MemoryWriter", L"FreezeManager", L"PointerScanner"
        };

        setStatus(status, L"Compiling shared Cheat Wizard sources...");
        std::vector<fs::path> coreObjects;
        for (const auto& name : coreNames) {
            coreObjects.push_back(compileSource(
                compiler, sourceRoot, objectDirectory,
                {fs::path(L"src") / (name + L".cpp"), name + L".o", {}}));
        }

        const fs::path protocolObject = compileSource(
            compiler, sourceRoot, objectDirectory,
            {L"src/EngineProtocol.cpp", L"EngineProtocol.o", {}});
        const fs::path pipeObject = compileSource(
            compiler, sourceRoot, objectDirectory,
            {L"src/EnginePipe.cpp", L"EnginePipe.o", {}});
        const fs::path clientObject = compileSource(
            compiler, sourceRoot, objectDirectory,
            {L"src/EngineClient.cpp", L"EngineClient.o", {}});
        const fs::path frontendObject = compileSource(
            compiler, sourceRoot, objectDirectory,
            {L"src/EngineFrontend.cpp", L"EngineFrontend.o", {}});

        std::vector<fs::path> engineCoreObjects;
        for (const auto& name : engineCoreNames) {
            engineCoreObjects.push_back(compileSource(
                compiler, sourceRoot, objectDirectory,
                {fs::path(L"src") / (name + L".cpp"), name + L".o", {}}));
        }

        setStatus(status, L"Building local engine...");
        const fs::path engineMain = compileSource(
            compiler, sourceRoot, objectDirectory,
            {L"src/EngineMain.cpp", L"EngineMain.o", {}});
        const fs::path engineVersion = compileResource(
            windres,
            sourceRoot / L"resources" / L"engine-version.rc",
            objectDirectory / L"engine-version.o",
            workspace);

        std::vector<fs::path> engineObjects = coreObjects;
        engineObjects.insert(engineObjects.end(), engineCoreObjects.begin(), engineCoreObjects.end());
        engineObjects.push_back(protocolObject);
        engineObjects.push_back(pipeObject);
        engineObjects.push_back(engineMain);
        engineObjects.push_back(engineVersion);
        const fs::path engineExe = productDirectory / L"cw-engine.exe";
        linkExecutable(compiler, engineObjects, {L"-ladvapi32"}, engineExe, false, true, workspace);

        std::string peError;
        if (!validatePe(engineExe, IMAGE_SUBSYSTEM_WINDOWS_CUI, peError)) {
            throw std::runtime_error("cw-engine.exe validation failed: " + peError);
        }
        std::string versionOutput;
        if (!runProcess(engineExe, {L"--version"}, workspace, exitCode, &versionOutput) ||
            exitCode != 0 ||
            versionOutput.find("protocol 1.1") == std::string::npos) {
            throw std::runtime_error("Generated engine failed protocol/version self-check");
        }

        setStatus(status, L"Building Cheat Wizard GUI...");
        const fs::path guiMain = compileSource(
            compiler, sourceRoot, objectDirectory,
            {L"portable_win/CW_GUI_NoCRT.cpp", L"CW_GUI_NoCRT.o", {L"CW_USE_STANDARD_CRT=1"}});
        const fs::path guiBridge = compileSource(
            compiler, sourceRoot, objectDirectory,
            {L"portable_win/GuiEngineBridge.cpp", L"GuiEngineBridge.o", {}});
        const fs::path guiEntry = compileSource(
            compiler, sourceRoot, objectDirectory,
            {L"portable_win/StandardCRTEntry.cpp", L"StandardCRTEntryGui.o", {L"CW_CRT_ENTRY_GUI=1"}});
        const fs::path guiVersion = compileResource(
            windres,
            sourceRoot / L"resources" / L"gui-version.rc",
            objectDirectory / L"gui-version.o",
            workspace);

        std::vector<fs::path> guiObjects = coreObjects;
        guiObjects.push_back(protocolObject);
        guiObjects.push_back(pipeObject);
        guiObjects.push_back(clientObject);
        guiObjects.push_back(frontendObject);
        guiObjects.push_back(guiBridge);
        guiObjects.push_back(guiMain);
        guiObjects.push_back(guiEntry);
        guiObjects.push_back(guiVersion);
        const fs::path guiExe = productDirectory / L"Cheat Wizard.exe";
        linkExecutable(
            compiler,
            guiObjects,
            {L"-lbcrypt", L"-ladvapi32", L"-luser32", L"-lgdi32", L"-lmsimg32"},
            guiExe,
            true,
            false,
            workspace);
        if (!validatePe(guiExe, IMAGE_SUBSYSTEM_WINDOWS_GUI, peError)) {
            throw std::runtime_error("Cheat Wizard.exe validation failed: " + peError);
        }

        setStatus(status, L"Building trainer runtime...");
        const fs::path trainerRuntimeMain = compileSource(
            compiler, sourceRoot, objectDirectory,
            {L"portable_win/TrainerRuntime_NoCRT.cpp", L"TrainerRuntime_NoCRT.o", {L"CW_USE_STANDARD_CRT=1"}});
        const fs::path trainerRuntimeEntry = compileSource(
            compiler, sourceRoot, objectDirectory,
            {L"portable_win/StandardCRTEntry.cpp", L"StandardCRTEntryTrainer.o", {L"CW_CRT_ENTRY_TRAINER=1"}});
        const fs::path trainerRuntimeVersion = compileResource(
            windres,
            sourceRoot / L"resources" / L"trainer-runtime-version.rc",
            objectDirectory / L"trainer-runtime-version.o",
            workspace);
        const fs::path trainerRuntime = workspace / L"trainer-runtime-template.exe";
        linkExecutable(
            compiler,
            {trainerRuntimeMain, trainerRuntimeEntry, trainerRuntimeVersion},
            {L"-luser32", L"-lgdi32"},
            trainerRuntime,
            true,
            false,
            workspace);
        if (!validatePe(trainerRuntime, IMAGE_SUBSYSTEM_WINDOWS_GUI, peError)) {
            throw std::runtime_error("Trainer runtime validation failed: " + peError);
        }

        setStatus(status, L"Building trainer builder...");
        const fs::path trainerBlob = generatedDirectory / L"TrainerRuntimeBlob.hpp";
        writeTrainerBlobHeader(trainerRuntime, trainerBlob);
        const fs::path trainerBuilderMain = compileSource(
            compiler,
            sourceRoot,
            objectDirectory,
            {L"portable_win/TrainerBuilder_NoCRT.cpp", L"TrainerBuilder_NoCRT.o", {L"CW_USE_STANDARD_CRT=1"}},
            {generatedDirectory});
        const fs::path trainerBuilderEntry = compileSource(
            compiler, sourceRoot, objectDirectory,
            {L"portable_win/StandardCRTEntry.cpp", L"StandardCRTEntryBuilder.o", {L"CW_CRT_ENTRY_BUILDER=1"}});
        const fs::path trainerBuilderVersion = compileResource(
            windres,
            sourceRoot / L"resources" / L"trainer-builder-version.rc",
            objectDirectory / L"trainer-builder-version.o",
            workspace);
        const fs::path trainerBuilderExe = productDirectory / L"cw-trainer-builder.exe";
        linkExecutable(
            compiler,
            {trainerBuilderMain, trainerBuilderEntry, trainerBuilderVersion},
            {},
            trainerBuilderExe,
            false,
            false,
            workspace);
        if (!validatePe(trainerBuilderExe, IMAGE_SUBSYSTEM_WINDOWS_CUI, peError)) {
            throw std::runtime_error("cw-trainer-builder.exe validation failed: " + peError);
        }

        setStatus(status, L"Writing manifests and support files...");
        const std::string engineHash = sha256File(engineExe);
        writeEngineManifest(productDirectory / L"cw-engine.build.json", metadata, engineHash);

        const fs::path localesSource = sourceRoot / L"locales";
        const fs::path localesDestination = productDirectory / L"locales";
        fs::create_directories(localesDestination);
        copyTreeFile(localesSource / L"en-US.json", localesDestination / L"en-US.json");
        copyTreeFile(localesSource / L"pt-BR.json", localesDestination / L"pt-BR.json");
        copyTreeFile(sourceRoot / L"LICENSE", productDirectory / L"LICENSE");
        copyTreeFile(sourceRoot / L"NOTICE", productDirectory / L"NOTICE");

        std::ofstream readme(productDirectory / L"README.txt", std::ios::binary | std::ios::trunc);
        readme
            << "Cheat Wizard " << metadata.at("productVersion") << "\r\n"
            << "Built locally from the source revision embedded in Cheat-Wizard-Builder.exe.\r\n"
            << "Run Cheat Wizard.exe to start Cheat Wizard.\r\n"
            << "To rebuild or repair the application, run Cheat-Wizard-Builder.exe again.\r\n";
        readme.close();

        std::map<std::string, std::string> hashes{
            {"cw-engine.exe", engineHash},
            {"Cheat Wizard.exe", sha256File(guiExe)},
            {"cw-trainer-builder.exe", sha256File(trainerBuilderExe)}
        };
        writeProductManifest(productDirectory / L"cw-build-manifest.json", metadata, hashes);

        setStatus(status, L"Installing locally built Cheat Wizard...");
        atomicInstallDirectory(productDirectory, outputDirectory);

        std::error_code cleanupError;
        fs::remove_all(workspace, cleanupError);
        setStatus(status, L"Build complete.");
        return 0;
    }
    catch (...) {
        std::error_code cleanupError;
        fs::remove_all(workspace, cleanupError);
        throw;
    }
}

void writeFailureLog(std::string_view message) {
    try {
        std::ofstream output(executableDirectory() / L"Cheat-Wizard-Builder-error.txt", std::ios::binary | std::ios::trunc);
        output << message << "\n";
    } catch (...) {
    }
}

bool launchGui(const fs::path& outputDirectory) {
    const fs::path gui = outputDirectory / L"Cheat Wizard.exe";
    HINSTANCE result = ShellExecuteW(nullptr, L"open", gui.c_str(), nullptr, outputDirectory.c_str(), SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(result) > 32;
}

struct UiState {
    HWND window{};
    HWND status{};
    HWND button{};
    HWND output{};
    HWND progress{};
    HFONT titleFont{};
    HFONT bodyFont{};
    fs::path outputDirectory;
    bool building{};
};

UiState g_ui;

int progressForStatus(std::wstring_view value) {
    if (value == L"Preparing embedded source and toolchain...") return 8;
    if (value == L"Compiling shared Cheat Wizard sources...") return 25;
    if (value == L"Building local engine...") return 45;
    if (value == L"Building Cheat Wizard GUI...") return 60;
    if (value == L"Building trainer runtime...") return 72;
    if (value == L"Building trainer builder...") return 82;
    if (value == L"Writing manifests and support files...") return 90;
    if (value == L"Installing locally built Cheat Wizard...") return 97;
    if (value == L"Build complete.") return 100;
    return -1;
}

void postStatus(HWND window, const std::wstring& value) {
    auto* text = new std::wstring(value);
    const int progress = progressForStatus(value);
    const WPARAM progressParam = progress >= 0 ? static_cast<WPARAM>(progress + 1) : 0;
    if (!PostMessageW(window, WM_CW_STATUS, progressParam, reinterpret_cast<LPARAM>(text))) delete text;
}

DWORD WINAPI buildThread(void* parameter) {
    HWND window = static_cast<HWND>(parameter);
    try {
        buildProduct(g_ui.outputDirectory, [window](const std::wstring& value) {
            postStatus(window, value);
        });
        PostMessageW(window, WM_CW_DONE, 0, 0);
    }
    catch (const std::exception& error) {
        writeFailureLog(error.what());
        auto* message = new std::wstring(utf8ToWide(error.what()));
        if (!PostMessageW(window, WM_CW_DONE, 1, reinterpret_cast<LPARAM>(message))) delete message;
    }
    return 0;
}

LRESULT CALLBACK windowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE: {
            g_ui.titleFont = CreateFontW(
                -24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            g_ui.bodyFont = CreateFontW(
                -16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT bodyFont = g_ui.bodyFont
                ? g_ui.bodyFont
                : static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

            HWND title = CreateWindowExW(
                0, L"STATIC", L"Cheat Wizard Builder",
                WS_CHILD | WS_VISIBLE,
                24, 20, 420, 34,
                window, nullptr, nullptr, nullptr);
            HWND subtitle = CreateWindowExW(
                0, L"STATIC", L"Local source build - no Visual Studio required",
                WS_CHILD | WS_VISIBLE,
                24, 54, 540, 24,
                window, nullptr, nullptr, nullptr);
            HWND description = CreateWindowExW(
                0, L"STATIC",
                L"Builds Cheat Wizard locally using the source and compiler embedded in this file.",
                WS_CHILD | WS_VISIBLE,
                24, 86, 540, 32,
                window, nullptr, nullptr, nullptr);
            HWND outputLabel = CreateWindowExW(
                0, L"STATIC", L"Install folder",
                WS_CHILD | WS_VISIBLE,
                24, 124, 540, 22,
                window, nullptr, nullptr, nullptr);
            g_ui.output = CreateWindowExW(
                0, L"STATIC",
                g_ui.outputDirectory.wstring().c_str(),
                WS_CHILD | WS_VISIBLE | SS_PATHELLIPSIS,
                24, 146, 540, 24,
                window, nullptr, nullptr, nullptr);
            g_ui.progress = CreateWindowExW(
                0, PROGRESS_CLASSW, nullptr,
                WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                24, 184, 540, 18,
                window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kProgressId)), nullptr, nullptr);
            g_ui.status = CreateWindowExW(
                0, L"STATIC", L"Ready to build.",
                WS_CHILD | WS_VISIBLE,
                24, 210, 540, 28,
                window, nullptr, nullptr, nullptr);
            g_ui.button = CreateWindowExW(
                0, L"BUTTON", L"Build && Launch",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                24, 248, 180, 40,
                window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kButtonId)), nullptr, nullptr);

            if (g_ui.progress) {
                SendMessageW(g_ui.progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
                SendMessageW(g_ui.progress, PBM_SETPOS, 0, 0);
            }
            SendMessageW(title, WM_SETFONT, reinterpret_cast<WPARAM>(
                g_ui.titleFont ? g_ui.titleFont : bodyFont), TRUE);
            SendMessageW(subtitle, WM_SETFONT, reinterpret_cast<WPARAM>(bodyFont), TRUE);
            SendMessageW(description, WM_SETFONT, reinterpret_cast<WPARAM>(bodyFont), TRUE);
            SendMessageW(outputLabel, WM_SETFONT, reinterpret_cast<WPARAM>(bodyFont), TRUE);
            SendMessageW(g_ui.output, WM_SETFONT, reinterpret_cast<WPARAM>(bodyFont), TRUE);
            SendMessageW(g_ui.status, WM_SETFONT, reinterpret_cast<WPARAM>(bodyFont), TRUE);
            SendMessageW(g_ui.button, WM_SETFONT, reinterpret_cast<WPARAM>(bodyFont), TRUE);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == kButtonId && !g_ui.building) {
                g_ui.building = true;
                EnableWindow(g_ui.button, FALSE);
                SetWindowTextW(g_ui.button, L"Building...");
                SetWindowTextW(g_ui.status, L"Starting local build...");
                if (g_ui.progress) SendMessageW(g_ui.progress, PBM_SETPOS, 2, 0);
                HANDLE thread = CreateThread(nullptr, 0, buildThread, window, 0, nullptr);
                if (!thread) {
                    g_ui.building = false;
                    EnableWindow(g_ui.button, TRUE);
                    SetWindowTextW(g_ui.button, L"Build && Launch");
                    SetWindowTextW(g_ui.status, L"Could not start build worker.");
                    if (g_ui.progress) SendMessageW(g_ui.progress, PBM_SETPOS, 0, 0);
                } else {
                    CloseHandle(thread);
                }
                return 0;
            }
            break;
        case WM_CW_STATUS: {
            auto* text = reinterpret_cast<std::wstring*>(lParam);
            if (text) {
                SetWindowTextW(g_ui.status, text->c_str());
                delete text;
            }
            if (wParam > 0 && g_ui.progress) {
                SendMessageW(g_ui.progress, PBM_SETPOS, static_cast<WPARAM>(wParam - 1), 0);
            }
            return 0;
        }
        case WM_CW_DONE:
            g_ui.building = false;
            if (wParam == 0) {
                if (g_ui.progress) SendMessageW(g_ui.progress, PBM_SETPOS, 100, 0);
                SetWindowTextW(g_ui.button, L"Done");
                SetWindowTextW(g_ui.status, L"Build complete. Launching Cheat Wizard...");
                if (!launchGui(g_ui.outputDirectory)) {
                    EnableWindow(g_ui.button, TRUE);
                    SetWindowTextW(g_ui.button, L"Build && Launch");
                    MessageBoxW(
                        window,
                        L"Cheat Wizard was built successfully, but Cheat Wizard.exe could not be launched automatically.",
                        L"Cheat Wizard Builder",
                        MB_OK | MB_ICONWARNING);
                } else {
                    SetWindowTextW(g_ui.status, L"Done. Cheat Wizard is starting...");
                    SetTimer(window, kAutoCloseTimerId, 900, nullptr);
                }
            } else {
                EnableWindow(g_ui.button, TRUE);
                SetWindowTextW(g_ui.button, L"Build && Launch");
                auto* error = reinterpret_cast<std::wstring*>(lParam);
                const std::wstring errorMessage = error ? *error : L"Unknown build error.";
                delete error;
                SetWindowTextW(g_ui.status, L"Build failed. See Cheat-Wizard-Builder-error.txt.");
                MessageBoxW(window, errorMessage.c_str(), L"Cheat Wizard Builder", MB_OK | MB_ICONERROR);
            }
            return 0;
        case WM_TIMER:
            if (wParam == kAutoCloseTimerId) {
                KillTimer(window, kAutoCloseTimerId);
                DestroyWindow(window);
                return 0;
            }
            break;
        case WM_CLOSE:
            if (g_ui.building) {
                MessageBoxW(window, L"Wait for the local build to finish before closing.", L"Cheat Wizard Builder", MB_OK);
                return 0;
            }
            DestroyWindow(window);
            return 0;
        case WM_DESTROY:
            if (g_ui.titleFont) {
                DeleteObject(g_ui.titleFont);
                g_ui.titleFont = nullptr;
            }
            if (g_ui.bodyFont) {
                DeleteObject(g_ui.bodyFont);
                g_ui.bodyFont = nullptr;
            }
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

struct Options {
    bool headless{};
    bool launch{};
    bool version{};
    fs::path outputDirectory;
};

Options parseOptions() {
    Options options;
    options.outputDirectory = executableDirectory() / L"Cheat-Wizard";

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) throw std::runtime_error("Could not parse command line");
    for (int i = 1; i < argc; ++i) {
        const std::wstring_view arg(argv[i]);
        if (arg == L"--headless") {
            options.headless = true;
        } else if (arg == L"--launch") {
            options.launch = true;
        } else if (arg == L"--version") {
            options.version = true;
        } else if (arg == L"--output-dir" && i + 1 < argc) {
            options.outputDirectory = fs::absolute(argv[++i]);
        } else {
            LocalFree(argv);
            throw std::runtime_error(
                "Usage: Cheat-Wizard-Builder.exe [--headless] [--output-dir <directory>] [--launch] [--version]");
        }
    }
    LocalFree(argv);
    return options;
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    try {
        const Options options = parseOptions();
        if (options.version) {
            MessageBoxW(
                nullptr,
                (std::wstring(L"Cheat Wizard Builder v") + kBuilderVersion).c_str(),
                L"Cheat Wizard Builder",
                MB_OK | MB_ICONINFORMATION);
            return 0;
        }

        if (options.headless) {
            try {
                const int result = buildProduct(options.outputDirectory, {});
                if (result == 0 && options.launch) launchGui(options.outputDirectory);
                return result;
            }
            catch (const std::exception& error) {
                writeFailureLog(error.what());
                return 2;
            }
        }

        g_ui.outputDirectory = options.outputDirectory;

        INITCOMMONCONTROLSEX controls{};
        controls.dwSize = sizeof(controls);
        controls.dwICC = ICC_PROGRESS_CLASS;
        if (!InitCommonControlsEx(&controls)) {
            throw std::runtime_error("Could not initialize Windows common controls");
        }

        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = windowProc;
        windowClass.hInstance = instance;
        windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(kAppIconResourceId));
        windowClass.hIconSm = static_cast<HICON>(LoadImageW(
            instance,
            MAKEINTRESOURCEW(kAppIconResourceId),
            IMAGE_ICON,
            16,
            16,
            LR_DEFAULTCOLOR));
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        windowClass.lpszClassName = L"CheatWizardStandaloneBuilder";
        if (!RegisterClassExW(&windowClass)) {
            throw std::runtime_error("Could not register builder window");
        }

        g_ui.window = CreateWindowExW(
            0,
            windowClass.lpszClassName,
            L"Cheat Wizard Builder",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            620,
            340,
            nullptr,
            nullptr,
            instance,
            nullptr);
        if (!g_ui.window) throw std::runtime_error("Could not create builder window");

        ShowWindow(g_ui.window, showCommand);
        UpdateWindow(g_ui.window);

        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        return static_cast<int>(message.wParam);
    }
    catch (const std::exception& error) {
        writeFailureLog(error.what());
        MessageBoxW(nullptr, utf8ToWide(error.what()).c_str(), L"Cheat Wizard Builder", MB_OK | MB_ICONERROR);
        return 2;
    }
}

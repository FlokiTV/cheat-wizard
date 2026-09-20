#include "cw/PointerScanner.hpp"

#include "cw/PointerAlgorithms.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <new>

namespace cw {
namespace {

constexpr SIZE_T kChunkSize = 4ull * 1024ull * 1024ull;
constexpr std::size_t kMaxTargetedNodes = 300'000;

bool readableProtection(DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) return false;
    switch (protect & 0xFFu) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

bool writableProtection(DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) return false;
    switch (protect & 0xFFu) {
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

bool readableRegion(const MEMORY_BASIC_INFORMATION& mbi, const PointerScanOptions& options) {
    if (mbi.State != MEM_COMMIT || !readableProtection(mbi.Protect)) return false;
    if (options.writableOnly && !writableProtection(mbi.Protect)) return false;
    if (options.privateOnly && mbi.Type != MEM_PRIVATE) return false;
    return true;
}

std::size_t effectiveAlignment(const PointerScanOptions& options, std::size_t pointerSize) {
    return options.alignment == 0 ? pointerSize : options.alignment;
}

std::vector<PointerModule> toPointerModules(const std::vector<ModuleInfo>& modules) {
    std::vector<PointerModule> out;
    out.reserve(modules.size());
    for (const auto& module : modules) {
        out.push_back(PointerModule{module.base, module.size, module.name});
    }
    return out;
}

std::optional<std::uintptr_t> addSignedOffset(std::uintptr_t base, std::int64_t offset) {
    if (offset >= 0) {
        const auto amount = static_cast<std::uint64_t>(offset);
        if (amount > static_cast<std::uint64_t>((std::numeric_limits<std::uintptr_t>::max)() - base)) return std::nullopt;
        return base + static_cast<std::uintptr_t>(amount);
    }
    const auto magnitude = static_cast<std::uint64_t>(-(offset + 1)) + 1u;
    if (magnitude > static_cast<std::uint64_t>(base)) return std::nullopt;
    return base - static_cast<std::uintptr_t>(magnitude);
}

bool sameModuleName(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    auto lower = [](wchar_t c) {
        return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
    };
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (lower(a[i]) != lower(b[i])) return false;
    }
    return true;
}

const ModuleInfo* moduleForAddress(
    const std::vector<ModuleInfo>& modules,
    std::uintptr_t address,
    const std::wstring& rootModuleName)
{
    for (const auto& module : modules) {
        if (!module.contains(address)) continue;
        if (!rootModuleName.empty() && !sameModuleName(module.name, rootModuleName)) continue;
        return &module;
    }
    return nullptr;
}

bool regionOverlapsModule(
    std::uintptr_t begin,
    std::uintptr_t end,
    const std::vector<ModuleInfo>& modules)
{
    for (const auto& module : modules) {
        const auto moduleBegin = module.base;
        auto moduleEnd = module.base + static_cast<std::uintptr_t>(module.size);
        if (moduleEnd < moduleBegin) moduleEnd = (std::numeric_limits<std::uintptr_t>::max)();
        if (begin < moduleEnd && end > moduleBegin) return true;
    }
    return false;
}

bool readableTargetedRegion(
    const MEMORY_BASIC_INFORMATION& mbi,
    const PointerScanOptions& options,
    const std::vector<ModuleInfo>& modules)
{
    if (mbi.State != MEM_COMMIT || !readableProtection(mbi.Protect)) return false;
    if (options.privateOnly && mbi.Type != MEM_PRIVATE) return false;
    if (!options.writableOnly || writableProtection(mbi.Protect)) return true;

    const auto begin = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
    auto end = begin + static_cast<std::uintptr_t>(mbi.RegionSize);
    if (end < begin) end = (std::numeric_limits<std::uintptr_t>::max)();
    // Preserve static roots in read-only image pages while still skipping
    // unrelated read-only mappings when writableOnly is requested.
    return regionOverlapsModule(begin, end, modules);
}

std::size_t countIndexedCandidates(
    const std::vector<PointerEntry>& index,
    std::uintptr_t target,
    const PointerScanOptions& options)
{
    const auto low = target >= options.maxOffset ? target - options.maxOffset : 0;
    const auto maxAddress = (std::numeric_limits<std::uintptr_t>::max)();
    const auto high = options.maxNegativeOffset > maxAddress - target
        ? maxAddress
        : target + options.maxNegativeOffset;
    const auto first = std::lower_bound(index.begin(), index.end(), PointerEntry{low, 0});
    const auto last = std::upper_bound(index.begin(), index.end(), PointerEntry{high, maxAddress});
    return static_cast<std::size_t>(last - first);
}

void normalizeChains(std::vector<PointerChain>& chains) {
    auto lessChain = [](const PointerChain& a, const PointerChain& b) {
        if (a.moduleName != b.moduleName) return a.moduleName < b.moduleName;
        if (a.rootOffset != b.rootOffset) return a.rootOffset < b.rootOffset;
        return a.offsets < b.offsets;
    };
    auto equalChain = [](const PointerChain& a, const PointerChain& b) {
        return a.moduleName == b.moduleName &&
               a.rootOffset == b.rootOffset &&
               a.offsets == b.offsets;
    };
    std::sort(chains.begin(), chains.end(), lessChain);
    chains.erase(std::unique(chains.begin(), chains.end(), equalChain), chains.end());
}

} // namespace

void PointerScanner::setProcess(HANDLE process, std::size_t pointerSize, std::vector<ModuleInfo> modules) {
    process_ = process;
    pointerSize_ = pointerSize;
    modules_ = std::move(modules);
    clearIndex();
    resetCancel();
    // Deliberately keep chains_: this permits pointer-rescan after restarting
    // and reattaching to the target. clearChains() is explicit.
}

void PointerScanner::clearIndex() {
    index_.clear();
    index_.shrink_to_fit();
}

void PointerScanner::clearChains() {
    chains_.clear();
    chains_.shrink_to_fit();
    chainPointerSize_ = 0;
}

void PointerScanner::reportProgress(const PointerScanStats& stats) const {
    if (!progressCallback_) return;
    progressCallback_(PointerProgress{stats.bytesRead, stats.regionsRead, index_.size()});
}

bool PointerScanner::buildIndex(const PointerScanOptions& options, PointerScanStats& stats) {
    clearIndex();
    if (!process_ || (pointerSize_ != 4 && pointerSize_ != 8)) return false;

    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    const auto minimum = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto maximum = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
    const std::size_t pageSize = si.dwPageSize ? static_cast<std::size_t>(si.dwPageSize) : 4096u;

    struct ReadableRange {
        std::uintptr_t begin{};
        std::uintptr_t end{};
    };
    std::vector<ReadableRange> readableTargets;
    std::vector<std::byte> buffer;
    try {
        buffer.resize(static_cast<std::size_t>(kChunkSize) + pointerSize_ - 1);
        index_.reserve((std::min)(options.maxIndexEntries, std::size_t{1'000'000}));

        // A bit-pattern is only useful as a pointer candidate when it targets
        // committed readable memory. Keeping this map up front prevents random
        // integer data from consuming the global index budget before real heap
        // pointers in later regions are reached.
        std::uintptr_t probe = minimum;
        while (probe < maximum) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(probe), &mbi, sizeof(mbi))) break;
            const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            auto regionEnd = regionBase + static_cast<std::uintptr_t>(mbi.RegionSize);
            if (regionEnd <= probe) break;
            if (mbi.State == MEM_COMMIT && readableProtection(mbi.Protect)) {
                if (!readableTargets.empty() && readableTargets.back().end == regionBase) {
                    readableTargets.back().end = regionEnd;
                } else {
                    readableTargets.push_back(ReadableRange{regionBase, regionEnd});
                }
            }
            probe = regionEnd;
        }
    } catch (const std::bad_alloc&) {
        return false;
    }
    if (readableTargets.empty()) return false;

    auto targetsReadableMemory = [&](std::uintptr_t value) {
        const auto it = std::upper_bound(
            readableTargets.begin(), readableTargets.end(), value,
            [](std::uintptr_t address, const ReadableRange& range) {
                return address < range.begin;
            });
        if (it == readableTargets.begin()) return false;
        const auto& range = *(it - 1);
        return value >= range.begin && value < range.end;
    };

    const std::size_t alignment = effectiveAlignment(options, pointerSize_);
    if (alignment == 0 || alignment > 8 || (alignment & (alignment - 1)) != 0) return false;

    auto processBuffer = [&](std::uintptr_t base, const std::byte* data,
                             std::size_t available, std::size_t primary) -> bool {
        if (available < pointerSize_ || primary == 0) return true;
        std::size_t start = 0;
        const auto rem = static_cast<std::size_t>(base % alignment);
        if (rem != 0) start = alignment - rem;

        for (std::size_t offset = start;
             offset < primary && offset + pointerSize_ <= available;
             offset += alignment) {
            std::uintptr_t value = 0;
            if (pointerSize_ == 4) {
                std::uint32_t v{};
                std::memcpy(&v, data + offset, sizeof(v));
                value = static_cast<std::uintptr_t>(v);
            } else {
                std::uint64_t v{};
                std::memcpy(&v, data + offset, sizeof(v));
                if (v > (std::numeric_limits<std::uintptr_t>::max)()) continue;
                value = static_cast<std::uintptr_t>(v);
            }

            if (value < minimum || value >= maximum || !targetsReadableMemory(value)) continue;
            index_.push_back(PointerEntry{value, base + offset});
            if (index_.size() >= options.maxIndexEntries) {
                stats.indexTruncated = true;
                return false;
            }
        }
        return true;
    };

    auto readAndProcess = [&](std::uintptr_t base, std::size_t primary, std::uintptr_t regionEnd) -> bool {
        std::size_t extra = 0;
        if (base + primary < regionEnd && pointerSize_ > 1) extra = pointerSize_ - 1;
        auto toRead = primary + extra;
        if (base + toRead > regionEnd) toRead = static_cast<std::size_t>(regionEnd - base);

        SIZE_T bytesRead = 0;
        const BOOL ok = ReadProcessMemory(
            process_, reinterpret_cast<LPCVOID>(base), buffer.data(), toRead, &bytesRead);
        if ((ok || bytesRead > 0) && bytesRead >= pointerSize_) {
            stats.bytesRead += bytesRead;
            return processBuffer(base, buffer.data(), static_cast<std::size_t>(bytesRead), primary);
        }
        return true; // caller may retry at page granularity
    };

    std::uintptr_t current = minimum;
    while (current < maximum) {
        if (cancelRequested_.load(std::memory_order_relaxed)) {
            stats.cancelled = true;
            break;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi))) break;
        const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const auto regionSize = static_cast<std::uintptr_t>(mbi.RegionSize);
        const auto regionEnd = regionBase + regionSize;
        if (regionEnd <= current) break;

        if (readableRegion(mbi, options)) {
            ++stats.regionsRead;
            std::uintptr_t p = regionBase;
            while (p < regionEnd) {
                if (cancelRequested_.load(std::memory_order_relaxed)) {
                    stats.cancelled = true;
                    break;
                }
                const auto remaining = regionEnd - p;
                const auto primary = static_cast<std::size_t>((std::min<std::uintptr_t>)(remaining, kChunkSize));

                SIZE_T probeRead = 0;
                std::size_t extra = (p + primary < regionEnd && pointerSize_ > 1) ? pointerSize_ - 1 : 0;
                std::size_t toRead = primary + extra;
                if (p + toRead > regionEnd) toRead = static_cast<std::size_t>(regionEnd - p);
                const BOOL ok = ReadProcessMemory(
                    process_, reinterpret_cast<LPCVOID>(p), buffer.data(), toRead, &probeRead);

                bool keepGoing = true;
                if ((ok || probeRead > 0) && probeRead >= pointerSize_) {
                    stats.bytesRead += probeRead;
                    keepGoing = processBuffer(p, buffer.data(), static_cast<std::size_t>(probeRead), primary);
                } else {
                    // A region can race with protection changes. Retry this chunk page-by-page
                    // so one bad page does not hide pointers in the rest of it.
                    const auto chunkEnd = p + primary;
                    for (auto page = p; page < chunkEnd; page += pageSize) {
                        const auto pagePrimary = static_cast<std::size_t>((std::min<std::uintptr_t>)(pageSize, chunkEnd - page));
                        if (!readAndProcess(page, pagePrimary, regionEnd)) {
                            keepGoing = false;
                            break;
                        }
                    }
                }

                reportProgress(stats);
                if (!keepGoing || stats.indexTruncated) break;
                p += primary;
            }
        }

        if (stats.cancelled || stats.indexTruncated) break;
        current = regionEnd;
    }

    std::sort(index_.begin(), index_.end());
    index_.erase(std::unique(index_.begin(), index_.end(), [](const PointerEntry& a, const PointerEntry& b) {
        return a.value == b.value && a.address == b.address;
    }), index_.end());
    return true;
}

bool PointerScanner::searchTargeted(
    std::uintptr_t target,
    const PointerScanOptions& options,
    PointerScanStats& stats)
{
    if (!process_ || (pointerSize_ != 4 && pointerSize_ != 8) || options.maxDepth == 0) return false;

    const std::size_t alignment = effectiveAlignment(options, pointerSize_);
    if (alignment == 0 || alignment > 8 || (alignment & (alignment - 1)) != 0) return false;

    struct TargetNode {
        std::uintptr_t address{};
        std::uint32_t parent{(std::numeric_limits<std::uint32_t>::max)()};
        std::int64_t offset{};
        std::uint64_t score{};
        std::size_t parentsSeen{};
    };

    const auto maxNodeBudget = (std::max)(std::size_t{1024}, options.maxSearchCandidates);
    const auto nodeCap = (std::min)(kMaxTargetedNodes, maxNodeBudget);

    std::vector<TargetNode> arena;
    std::vector<std::uint32_t> currentNodes;
    std::vector<std::uint32_t> nextNodes;
    std::vector<std::byte> buffer;
    try {
        arena.reserve(nodeCap);
        currentNodes.reserve((std::min)(nodeCap, std::size_t{65'536}));
        nextNodes.reserve((std::min)(nodeCap, std::size_t{65'536}));
        buffer.resize(static_cast<std::size_t>(kChunkSize) + pointerSize_ - 1);
    } catch (const std::bad_alloc&) {
        return false;
    }

    arena.push_back(TargetNode{target});
    currentNodes.push_back(0);
    stats.targetedUsed = true;

    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    const auto minimum = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto maximum = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
    const std::size_t pageSize = si.dwPageSize ? static_cast<std::size_t>(si.dwPageSize) : 4096u;
    const auto maxAddress = (std::numeric_limits<std::uintptr_t>::max)();

    auto absoluteOffset = [](std::int64_t value) -> std::uint64_t {
        return value >= 0
            ? static_cast<std::uint64_t>(value)
            : static_cast<std::uint64_t>(-(value + 1)) + 1u;
    };

    auto sortAndDedupFrontier = [&](std::vector<std::uint32_t>& nodes) {
        std::sort(nodes.begin(), nodes.end(), [&](std::uint32_t a, std::uint32_t b) {
            if (arena[a].address != arena[b].address) return arena[a].address < arena[b].address;
            if (arena[a].score != arena[b].score) return arena[a].score < arena[b].score;
            return a < b;
        });
        std::size_t out = 0;
        for (const auto index : nodes) {
            if (out != 0 && arena[nodes[out - 1]].address == arena[index].address) continue;
            nodes[out++] = index;
        }
        nodes.resize(out);
    };

    auto pickTarget = [&](std::uintptr_t value, std::uint32_t& targetIndex, std::int64_t& offset) -> bool {
        if (currentNodes.empty()) return false;
        const auto low = value >= options.maxNegativeOffset ? value - options.maxNegativeOffset : 0;
        const auto high = options.maxOffset > maxAddress - value ? maxAddress : value + options.maxOffset;

        auto lowerByAddress = [&](std::uintptr_t wanted, std::size_t begin, std::size_t end) {
            while (begin < end) {
                const auto mid = begin + (end - begin) / 2;
                if (arena[currentNodes[mid]].address < wanted) begin = mid + 1;
                else end = mid;
            }
            return begin;
        };
        auto upperByAddress = [&](std::uintptr_t wanted, std::size_t begin, std::size_t end) {
            while (begin < end) {
                const auto mid = begin + (end - begin) / 2;
                if (arena[currentNodes[mid]].address <= wanted) begin = mid + 1;
                else end = mid;
            }
            return begin;
        };

        const auto begin = lowerByAddress(low, 0, currentNodes.size());
        const auto end = upperByAddress(high, begin, currentNodes.size());
        if (begin >= end) return false;

        auto right = lowerByAddress(value, begin, end);
        bool have = false;
        std::size_t best = 0;
        std::uint64_t bestDistance = (std::numeric_limits<std::uint64_t>::max)();

        auto consider = [&](std::size_t position) {
            if (position < begin || position >= end) return;
            const auto address = arena[currentNodes[position]].address;
            const auto distance = address >= value
                ? static_cast<std::uint64_t>(address - value)
                : static_cast<std::uint64_t>(value - address);
            if (!have || distance < bestDistance ||
                (distance == bestDistance && arena[currentNodes[position]].score < arena[currentNodes[best]].score)) {
                best = position;
                bestDistance = distance;
                have = true;
            }
        };

        if (right < end) consider(right);
        if (right > begin) consider(right - 1);
        if (!have) return false;

        targetIndex = currentNodes[best];
        const auto targetAddress = arena[targetIndex].address;
        if (targetAddress >= value) {
            const auto diff = targetAddress - value;
            if (diff > options.maxOffset ||
                diff > static_cast<std::uintptr_t>((std::numeric_limits<std::int64_t>::max)())) return false;
            offset = static_cast<std::int64_t>(diff);
        } else {
            const auto diff = value - targetAddress;
            if (diff > options.maxNegativeOffset ||
                diff > static_cast<std::uintptr_t>((std::numeric_limits<std::int64_t>::max)())) return false;
            offset = -static_cast<std::int64_t>(diff);
        }
        return true;
    };

    auto wouldCycle = [&](std::uintptr_t slot, std::uint32_t tailIndex) {
        auto index = tailIndex;
        for (;;) {
            if (arena[index].address == slot) return true;
            const auto parent = arena[index].parent;
            if (parent == (std::numeric_limits<std::uint32_t>::max)()) break;
            index = parent;
        }
        return false;
    };

    auto addChain = [&](const ModuleInfo& module, std::uintptr_t slot,
                        std::int64_t firstOffset, std::uint32_t tailIndex) -> bool {
        if (chains_.size() >= options.maxChains) {
            stats.chainsTruncated = true;
            return false;
        }

        PointerChain chain;
        chain.moduleName = module.name;
        chain.rootOffset = slot - module.base;
        chain.offsets.push_back(firstOffset);

        auto index = tailIndex;
        while (arena[index].parent != (std::numeric_limits<std::uint32_t>::max)()) {
            chain.offsets.push_back(arena[index].offset);
            index = arena[index].parent;
        }

        chains_.push_back(std::move(chain));
        if (chains_.size() >= options.maxChains) {
            stats.chainsTruncated = true;
            return false;
        }
        return true;
    };

    for (std::size_t level = 0;
         level < options.maxDepth && !currentNodes.empty() && chains_.size() < options.maxChains;
         ++level) {
        if (cancelRequested_.load(std::memory_order_relaxed)) {
            stats.cancelled = true;
            break;
        }

        sortAndDedupFrontier(currentNodes);
        for (const auto index : currentNodes) arena[index].parentsSeen = 0;
        nextNodes.clear();

        stats.targetedDepth = level + 1;
        stats.targetedFrontier = currentNodes.size();

        auto processBuffer = [&](std::uintptr_t base, const std::byte* data,
                                 std::size_t available, std::size_t primary) -> bool {
            if (available < pointerSize_ || primary == 0) return true;
            std::size_t start = 0;
            const auto rem = static_cast<std::size_t>(base % alignment);
            if (rem != 0) start = alignment - rem;

            for (std::size_t byteOffset = start;
                 byteOffset < primary && byteOffset + pointerSize_ <= available;
                 byteOffset += alignment) {
                if (cancelRequested_.load(std::memory_order_relaxed)) {
                    stats.cancelled = true;
                    return false;
                }

                std::uintptr_t value = 0;
                if (pointerSize_ == 4) {
                    std::uint32_t raw{};
                    std::memcpy(&raw, data + byteOffset, sizeof(raw));
                    value = static_cast<std::uintptr_t>(raw);
                } else {
                    std::uint64_t raw{};
                    std::memcpy(&raw, data + byteOffset, sizeof(raw));
                    if (raw > (std::numeric_limits<std::uintptr_t>::max)()) continue;
                    value = static_cast<std::uintptr_t>(raw);
                }

                ++stats.targetedSlots;
                std::uint32_t tailIndex = 0;
                std::int64_t pointerOffset = 0;
                if (!pickTarget(value, tailIndex, pointerOffset)) continue;
                if (level == 0) ++stats.directCandidates;

                auto& tail = arena[tailIndex];
                if (tail.parentsSeen >= options.maxCandidatesPerNode) {
                    stats.branchLimitHit = true;
                    continue;
                }

                const auto slot = base + byteOffset;
                if (wouldCycle(slot, tailIndex)) continue;

                ++tail.parentsSeen;
                ++stats.targetedMatches;

                if (const auto* module = moduleForAddress(modules_, slot, options.rootModuleName)) {
                    if (!addChain(*module, slot, pointerOffset, tailIndex)) return false;
                    continue;
                }

                if (level + 1 >= options.maxDepth) continue;
                if (arena.size() >= nodeCap) {
                    stats.targetedTruncated = true;
                    continue;
                }

                TargetNode node;
                node.address = slot;
                node.parent = tailIndex;
                node.offset = pointerOffset;
                const auto offsetCost = absoluteOffset(pointerOffset);
                node.score = tail.score > (std::numeric_limits<std::uint64_t>::max)() - offsetCost
                    ? (std::numeric_limits<std::uint64_t>::max)()
                    : tail.score + offsetCost;
                arena.push_back(node);
                nextNodes.push_back(static_cast<std::uint32_t>(arena.size() - 1));
            }
            return true;
        };

        auto readAndProcess = [&](std::uintptr_t base, std::size_t primary, std::uintptr_t regionEnd) -> bool {
            std::size_t extra = 0;
            if (base + primary < regionEnd && pointerSize_ > 1) extra = pointerSize_ - 1;
            auto toRead = primary + extra;
            if (base + toRead > regionEnd) toRead = static_cast<std::size_t>(regionEnd - base);

            SIZE_T bytesRead = 0;
            const BOOL ok = ReadProcessMemory(
                process_, reinterpret_cast<LPCVOID>(base), buffer.data(), toRead, &bytesRead);
            if ((ok || bytesRead > 0) && bytesRead >= pointerSize_) {
                stats.bytesRead += bytesRead;
                return processBuffer(base, buffer.data(), static_cast<std::size_t>(bytesRead), primary);
            }
            return true;
        };

        std::uintptr_t currentAddress = minimum;
        bool keepSearching = true;
        while (currentAddress < maximum && keepSearching) {
            if (cancelRequested_.load(std::memory_order_relaxed)) {
                stats.cancelled = true;
                break;
            }

            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(currentAddress), &mbi, sizeof(mbi))) break;
            const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto regionSize = static_cast<std::uintptr_t>(mbi.RegionSize);
            auto regionEnd = regionBase + regionSize;
            if (regionEnd <= currentAddress) break;

            if (readableTargetedRegion(mbi, options, modules_)) {
                ++stats.regionsRead;
                std::uintptr_t p = regionBase;
                while (p < regionEnd) {
                    if (cancelRequested_.load(std::memory_order_relaxed)) {
                        stats.cancelled = true;
                        keepSearching = false;
                        break;
                    }

                    const auto remaining = regionEnd - p;
                    const auto primary = static_cast<std::size_t>((std::min<std::uintptr_t>)(remaining, kChunkSize));
                    SIZE_T probeRead = 0;
                    std::size_t extra = (p + primary < regionEnd && pointerSize_ > 1) ? pointerSize_ - 1 : 0;
                    std::size_t toRead = primary + extra;
                    if (p + toRead > regionEnd) toRead = static_cast<std::size_t>(regionEnd - p);
                    const BOOL ok = ReadProcessMemory(
                        process_, reinterpret_cast<LPCVOID>(p), buffer.data(), toRead, &probeRead);

                    bool processed = true;
                    if ((ok || probeRead > 0) && probeRead >= pointerSize_) {
                        stats.bytesRead += probeRead;
                        processed = processBuffer(p, buffer.data(), static_cast<std::size_t>(probeRead), primary);
                    } else {
                        const auto chunkEnd = p + primary;
                        for (auto page = p; page < chunkEnd; page += pageSize) {
                            const auto pagePrimary = static_cast<std::size_t>(
                                (std::min<std::uintptr_t>)(pageSize, chunkEnd - page));
                            if (!readAndProcess(page, pagePrimary, regionEnd)) {
                                processed = false;
                                break;
                            }
                        }
                    }

                    reportProgress(stats);
                    if (!processed || stats.cancelled || chains_.size() >= options.maxChains) {
                        keepSearching = false;
                        break;
                    }
                    p += primary;
                }
            }

            if (stats.cancelled || chains_.size() >= options.maxChains) break;
            currentAddress = regionEnd;
        }

        if (stats.cancelled || chains_.size() >= options.maxChains) break;

        // Match the historical Deep behavior: once static roots are found at a
        // depth, keep the shallowest useful set rather than rescanning all memory
        // for deeper and usually less stable variants.
        if (!chains_.empty()) break;
        if (nextNodes.empty()) break;

        sortAndDedupFrontier(nextNodes);
        currentNodes.swap(nextNodes);
    }

    normalizeChains(chains_);
    stats.chains = chains_.size();
    if (stats.targetedTruncated || stats.branchLimitHit) stats.chainsTruncated = true;
    return true;
}

PointerScanStats PointerScanner::captureIndex(const PointerScanOptions& options) {
    PointerScanStats stats;
    stats.pointerSize = pointerSize_;
    resetCancel();

    const auto indexStart = std::chrono::steady_clock::now();
    if (!buildIndex(options, stats)) {
        stats.indexMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - indexStart).count();
        stats.indexEntries = index_.size();
        return stats;
    }
    stats.indexMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - indexStart).count();
    stats.indexEntries = index_.size();
    return stats;
}

PointerScanStats PointerScanner::scan(std::uintptr_t target, const PointerScanOptions& options) {
    PointerScanStats stats;
    stats.pointerSize = pointerSize_;
    resetCancel();
    chains_.clear();
    chainPointerSize_ = pointerSize_;

    if (options.searchMode == PointerSearchMode::Targeted) {
        clearIndex();
        const auto searchStart = std::chrono::steady_clock::now();
        if (!searchTargeted(target, options, stats)) {
            stats.searchMs = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - searchStart).count();
            return stats;
        }
        stats.searchMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - searchStart).count();
        stats.chains = chains_.size();
        return stats;
    }

    const auto indexStart = std::chrono::steady_clock::now();
    if (!buildIndex(options, stats)) {
        stats.indexMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - indexStart).count();
        return stats;
    }
    stats.indexMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - indexStart).count();
    stats.indexEntries = index_.size();

    if (stats.cancelled) return stats;

    const auto searchStart = std::chrono::steady_clock::now();
    bool searchTruncated = false;
    PointerSearchDiagnostics diagnostics;
    stats.directCandidates = countIndexedCandidates(index_, target, options);
    chains_ = findPointerChains(
        index_, toPointerModules(modules_), target, options, &searchTruncated, &diagnostics);
    stats.searchCandidates = diagnostics.candidatesExamined;
    stats.searchBudgetHit = diagnostics.budgetHit;
    stats.branchLimitHit = diagnostics.branchLimitHit;
    stats.chains = chains_.size();
    stats.chainsTruncated = searchTruncated;

    const bool needsTargetedFallback =
        options.searchMode == PointerSearchMode::Auto &&
        chains_.empty() &&
        !stats.cancelled;

    if (needsTargetedFallback) {
        stats.targetedFallbackUsed = true;
        stats.directCandidates = 0;
        stats.chainsTruncated = false;
        chains_.clear();
        clearIndex();
        if (!searchTargeted(target, options, stats)) {
            stats.searchMs = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - searchStart).count();
            return stats;
        }
    }

    stats.searchMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - searchStart).count();
    stats.chains = chains_.size();
    return stats;
}

std::optional<std::uintptr_t> PointerScanner::readPointer(std::uintptr_t address) const {
    if (!process_) return std::nullopt;
    SIZE_T bytesRead = 0;
    if (pointerSize_ == 4) {
        std::uint32_t value{};
        if (!ReadProcessMemory(process_, reinterpret_cast<LPCVOID>(address), &value, sizeof(value), &bytesRead) ||
            bytesRead != sizeof(value)) return std::nullopt;
        return static_cast<std::uintptr_t>(value);
    }
    if (pointerSize_ == 8) {
        std::uint64_t value{};
        if (!ReadProcessMemory(process_, reinterpret_cast<LPCVOID>(address), &value, sizeof(value), &bytesRead) ||
            bytesRead != sizeof(value)) return std::nullopt;
        if (value > (std::numeric_limits<std::uintptr_t>::max)()) return std::nullopt;
        return static_cast<std::uintptr_t>(value);
    }
    return std::nullopt;
}

const ModuleInfo* PointerScanner::findModule(const std::wstring& name) const {
    auto lower = [](wchar_t c) {
        return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
    };
    for (const auto& module : modules_) {
        if (module.name.size() != name.size()) continue;
        bool equal = true;
        for (std::size_t i = 0; i < name.size(); ++i) {
            if (lower(module.name[i]) != lower(name[i])) {
                equal = false;
                break;
            }
        }
        if (equal) return &module;
    }
    return nullptr;
}

std::optional<std::uintptr_t> PointerScanner::resolve(const PointerChain& chain) const {
    const auto* module = findModule(chain.moduleName);
    if (!module) return std::nullopt;
    if (chain.rootOffset >= module->size) return std::nullopt;

    std::uintptr_t address = module->base + chain.rootOffset;
    for (const auto offset : chain.offsets) {
        const auto pointer = readPointer(address);
        if (!pointer) return std::nullopt;
        const auto next = addSignedOffset(*pointer, offset);
        if (!next) return std::nullopt;
        address = *next;
    }
    return address;
}

std::optional<std::uintptr_t> PointerScanner::resolve(std::size_t chainIndex) const {
    if (chainIndex >= chains_.size()) return std::nullopt;
    if (chainPointerSize_ != 0 && pointerSize_ != chainPointerSize_) return std::nullopt;
    return resolve(chains_[chainIndex]);
}

std::size_t PointerScanner::rescan(std::uintptr_t target) {
    if (!process_) return 0;
    if (chainPointerSize_ != 0 && pointerSize_ != chainPointerSize_) return 0;
    std::vector<PointerChain> kept;
    kept.reserve(chains_.size());
    for (const auto& chain : chains_) {
        const auto resolved = resolve(chain);
        if (resolved && *resolved == target) kept.push_back(chain);
    }
    chains_.swap(kept);
    return chains_.size();
}

} // namespace cw

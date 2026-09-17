#include "cw/PointerAlgorithms.hpp"

#include <algorithm>
#include <cwctype>
#include <limits>
#include <vector>

namespace cw {
namespace {

bool iequals(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(a[i]) != std::towlower(b[i])) return false;
    }
    return true;
}

const PointerModule* moduleForAddress(
    const std::vector<PointerModule>& modules,
    std::uintptr_t address,
    const std::wstring& rootModuleName)
{
    for (const auto& module : modules) {
        if (!module.contains(address)) continue;
        if (!rootModuleName.empty() && !iequals(module.name, rootModuleName)) continue;
        return &module;
    }
    return nullptr;
}

struct SearchContext {
    const std::vector<PointerEntry>& index;
    const std::vector<PointerModule>& modules;
    const PointerScanOptions& options;
    std::vector<PointerChain> chains;
    bool truncated{};
    std::size_t workUsed{};

    void dfs(
        std::uintptr_t current,
        std::size_t depth,
        const std::vector<std::int64_t>& tailOffsets,
        std::vector<std::uintptr_t>& path)
    {
        if (depth >= options.maxDepth || chains.size() >= options.maxChains ||
            workUsed >= options.maxSearchCandidates) {
            if (chains.size() >= options.maxChains || workUsed >= options.maxSearchCandidates) truncated = true;
            return;
        }

        const auto low = current >= options.maxOffset ? current - options.maxOffset : 0;
        const auto maxAddress = (std::numeric_limits<std::uintptr_t>::max)();
        const auto high = options.maxNegativeOffset > maxAddress - current
            ? maxAddress
            : current + options.maxNegativeOffset;

        PointerEntry keyLow{low, 0};
        PointerEntry keyHigh{high, maxAddress};
        const auto rangeBegin = std::lower_bound(index.begin(), index.end(), keyLow);
        const auto rangeEnd = std::upper_bound(index.begin(), index.end(), keyHigh);
        if (rangeBegin == rangeEnd) return;

        // Start at the closest stored pointer value and expand outwards. Small
        // field offsets are much more common than large ones and this ordering
        // finds useful chains sooner under a bounded search budget.
        const auto center = std::lower_bound(rangeBegin, rangeEnd, PointerEntry{current, 0});
        auto left = center;
        auto right = center;
        std::size_t candidates = 0;
        while (left != rangeBegin || right != rangeEnd) {
            if (++candidates > options.maxCandidatesPerNode || ++workUsed > options.maxSearchCandidates) {
                truncated = true;
                return;
            }

            bool takeLeft = false;
            if (left != rangeBegin && right != rangeEnd) {
                const auto& l = *(left - 1);
                const auto& r = *right;
                const auto ld = current >= l.value ? current - l.value : l.value - current;
                const auto rd = current >= r.value ? current - r.value : r.value - current;
                takeLeft = ld <= rd;
            } else {
                takeLeft = left != rangeBegin;
            }

            const PointerEntry& entry = takeLeft ? *--left : *right++;
            std::int64_t offset = 0;
            if (entry.value <= current) {
                const auto diff = current - entry.value;
                if (diff > options.maxOffset || diff > static_cast<std::uintptr_t>((std::numeric_limits<std::int64_t>::max)())) continue;
                offset = static_cast<std::int64_t>(diff);
            } else {
                const auto diff = entry.value - current;
                if (diff > options.maxNegativeOffset || diff > static_cast<std::uintptr_t>((std::numeric_limits<std::int64_t>::max)())) continue;
                offset = -static_cast<std::int64_t>(diff);
            }

            const auto slot = entry.address;
            if (std::find(path.begin(), path.end(), slot) != path.end()) continue;

            std::vector<std::int64_t> offsets;
            offsets.reserve(tailOffsets.size() + 1);
            offsets.push_back(offset);
            offsets.insert(offsets.end(), tailOffsets.begin(), tailOffsets.end());

            if (const auto* module = moduleForAddress(modules, slot, options.rootModuleName)) {
                PointerChain chain;
                chain.moduleName = module->name;
                chain.rootOffset = slot - module->base;
                chain.offsets = std::move(offsets);
                chains.push_back(std::move(chain));
                if (chains.size() >= options.maxChains) {
                    truncated = true;
                    return;
                }
                continue;
            }

            if (depth + 1 < options.maxDepth) {
                path.push_back(slot);
                dfs(slot, depth + 1, offsets, path);
                path.pop_back();
                if (chains.size() >= options.maxChains || workUsed >= options.maxSearchCandidates) return;
            }
        }
    }};

} // namespace

std::vector<PointerChain> findPointerChains(
    const std::vector<PointerEntry>& sortedIndex,
    const std::vector<PointerModule>& modules,
    std::uintptr_t target,
    const PointerScanOptions& options,
    bool* truncated)
{
    SearchContext ctx{sortedIndex, modules, options, {}, false};
    std::vector<std::uintptr_t> path;
    path.push_back(target);
    ctx.dfs(target, 0, {}, path);

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
    std::sort(ctx.chains.begin(), ctx.chains.end(), lessChain);
    ctx.chains.erase(std::unique(ctx.chains.begin(), ctx.chains.end(), equalChain), ctx.chains.end());

    if (truncated) *truncated = ctx.truncated;
    return ctx.chains;
}

} // namespace cw

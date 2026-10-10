// IG5 integration code. Ghidra's decompiler remains Apache-2.0 upstream code.
#include "ig5_decompiler.h"
#include "libdecomp.hh"
#include "funcdata.hh"
#include "flow.hh"
#include "printlanguage.hh"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <set>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <vector>

namespace {
using namespace ghidra;
const size_t image_budget = 64 * 1024 * 1024;
const size_t output_budget = 4 * 1024 * 1024;
std::mutex decompile_mutex;
std::string configured_specs;
bool library_initialized = false;

struct BudgetError : public std::runtime_error {
    explicit BudgetError(const char *what) : std::runtime_error(what) {}
};
class BoundedStream : public std::streambuf {
    size_t limit;
    std::string text;
protected:
    int_type overflow(int_type value) override {
        if (traits_type::eq_int_type(value, traits_type::eof())) return traits_type::not_eof(value);
        if (text.size() == limit) throw BudgetError("native text output budget exceeded");
        text.push_back(traits_type::to_char_type(value));
        return value;
    }
    std::streamsize xsputn(const char *data, std::streamsize count) override {
        if (count < 0 || static_cast<size_t>(count) > limit - text.size())
            throw BudgetError("native text output budget exceeded");
        text.append(data, static_cast<size_t>(count));
        return count;
    }
public:
    explicit BoundedStream(size_t maximum) : limit(maximum) {}
    const std::string &str() const { return text; }
};
struct Region {
    uint64_t start;
    uint32_t flags;
    std::vector<uint1> bytes;
};
class OwnedLoadImage : public LoadImage {
    std::vector<Region> regions;
    AddrSpace *space = nullptr;
    size_t read_bytes = 0;
public:
    explicit OwnedLoadImage(std::vector<Region> values) : LoadImage("ig5-owned-memory"), regions(std::move(values)) {}
    void attach(AddrSpace *value) { space = value; }
    void loadFill(uint1 *destination, int4 size, const Address &address) override {
        if (!space || address.getSpace() != space || size < 1 || size > 1024 * 1024)
            throw DataUnavailError("invalid native memory read");
        if (static_cast<size_t>(size) > 256 * 1024 * 1024 - read_bytes)
            throw BudgetError("native load image read budget exceeded");
        read_bytes += static_cast<size_t>(size);
        uint64_t cursor = address.getOffset();
        if (static_cast<uint64_t>(size - 1) > std::numeric_limits<uint64_t>::max() - cursor)
            throw DataUnavailError("native memory read arithmetic overflow");
        int4 remaining = size;
        while (remaining) {
            auto iter = std::upper_bound(regions.begin(), regions.end(), cursor,
                [](uint64_t value, const Region &region) { return value < region.start; });
            if (iter == regions.begin()) throw DataUnavailError("native memory read enters an unmapped region");
            --iter;
            const uint64_t offset = cursor - iter->start;
            if (offset >= iter->bytes.size()) throw DataUnavailError("native memory read enters an unmapped gap");
            size_t count = std::min(static_cast<size_t>(remaining), iter->bytes.size() - static_cast<size_t>(offset));
            std::memcpy(destination, iter->bytes.data() + static_cast<size_t>(offset), count);
            destination += count;
            remaining -= static_cast<int4>(count);
            cursor += count;
        }
    }
    std::string getArchType() const override { return "ig5-owned-memory"; }
    void adjustVma(long value) override {
        if (value) throw LowlevelError("native mapped image cannot be rebased implicitly");
    }
    void getReadonly(RangeList &ranges) const override {
        if (!space) return;
        for (const auto &region : regions)
            if (region.flags & IG5_DEC_READONLY)
                ranges.insertRange(space, region.start, region.start + region.bytes.size() - 1);
    }
    size_t readCount() const { return read_bytes; }
};
class MemoryArchitecture : public SleighArchitecture {
    std::vector<Region> mapped;
protected:
    void buildLoader(DocumentStorage &) override {
        collectSpecFiles(*errorstream);
        loader = new OwnedLoadImage(std::move(mapped));
    }
    void postSpecFile() override {
        Architecture::postSpecFile();
        static_cast<OwnedLoadImage *>(loader)->attach(getDefaultCodeSpace());
    }
public:
    MemoryArchitecture(const std::string &target, std::ostream *errors, std::vector<Region> regions)
        : SleighArchitecture("ig5-owned-memory", target, errors), mapped(std::move(regions)) {}
};
std::string escape(const std::string &value) {
    std::ostringstream result;
    result << '"';
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') result << '\\' << c;
        else if (c < 32) result << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(c);
        else result << c;
    }
    result << '"';
    return result.str();
}
std::string hexvalue(uint64_t value) {
    std::ostringstream text;
    text << "0x" << std::hex << value;
    return text.str();
}
int result(const std::string &value, char *output, size_t capacity, size_t *required, int status) {
    if (!required) return 2;
    *required = value.size() + 1;
    if (!output || capacity < *required) return 1;
    std::memcpy(output, value.c_str(), *required);
    return status;
}
std::string failure(const std::string &message, const char *stage, bool budget = false) {
    return "{\"ok\":false,\"engine\":\"IG5 Kernel\",\"core\":\"Ghidra native decompiler\","
           "\"jvmStarted\":false,\"commercialEngineUsed\":false,\"complete\":false,\"budgetExceeded\":" +
           std::string(budget ? "true" : "false") + ",\"stage\":" + escape(stage) + ",\"error\":" + escape(message) + "}";
}
int error_result(const char *message, const char *stage, char *output, size_t capacity, size_t *required,
                 int status, bool budget = false) noexcept {
    try {
        return result(failure(message, stage, budget), output, capacity, required, status);
    } catch (...) {
        // Even allocation while formatting an error cannot escape the C ABI.
        static const char fallback[] = "{\"ok\":false,\"complete\":false,\"budgetExceeded\":true,\"error\":\"native error output allocation failed\"}";
        *required = sizeof(fallback);
        if (!output || capacity < sizeof(fallback)) return 1;
        std::memcpy(output, fallback, sizeof(fallback));
        return 4;
    }
}
size_t bounded_string(const char *value, size_t maximum, const char *name) {
    if (!value) throw std::invalid_argument(std::string(name) + " is required");
    size_t size = 0;
    while (size <= maximum && value[size]) ++size;
    if (size == 0 || size > maximum) throw std::invalid_argument(std::string(name) + " has an invalid length");
    return size;
}
}

extern "C" IG5_DECOMPILER_API int ig5_decompiler_function(
    const char *spec_directory, const char *target,
    const ig5_decompiler_region *regions, size_t region_count,
    uint64_t entry, uint64_t function_begin, uint64_t function_end,
    uint32_t max_instructions, char *output, size_t capacity, size_t *required) {
    if (!required) return 2;
    const char *stage = "validate";
    try {
        std::lock_guard<std::mutex> serial(decompile_mutex);
        bounded_string(spec_directory, 32768, "spec_directory");
        bounded_string(target, 128, "target");
        if (!regions || !region_count || region_count > 512 || !max_instructions || max_instructions > 10000 ||
            function_end <= function_begin || function_end - function_begin > 16 * 1024 * 1024 ||
            entry < function_begin || entry >= function_end || capacity > 16 * 1024 * 1024)
            throw std::invalid_argument("invalid bounded decompiler arguments");
        std::vector<Region> mapped;
        size_t total = 0;
        bool entry_executable = false;
        for (size_t index = 0; index < region_count; ++index) {
            const auto &region = regions[index];
            if (!region.size || region.size > image_budget - total || region.data_length > region.size ||
                (region.data_length && !region.data) || region.flags & ~7u ||
                region.size > std::numeric_limits<uint64_t>::max() - region.start ||
                (region.data_length < region.size && !(region.flags & IG5_DEC_ZERO_FILL_TAIL)))
                throw std::invalid_argument("invalid mapped region or unspecified zero-fill tail");
            Region value;
            value.start = region.start;
            value.flags = region.flags;
            value.bytes.resize(static_cast<size_t>(region.size), 0);
            if (region.data_length) std::memcpy(value.bytes.data(), region.data, region.data_length);
            mapped.push_back(std::move(value));
            total += static_cast<size_t>(region.size);
            if (region.start <= entry && entry - region.start < region.size && region.flags & IG5_DEC_EXECUTABLE)
                entry_executable = true;
        }
        std::sort(mapped.begin(), mapped.end(), [](const Region &a, const Region &b) { return a.start < b.start; });
        for (size_t index = 1; index < mapped.size(); ++index)
            if (mapped[index].start < mapped[index - 1].start + mapped[index - 1].bytes.size())
                throw std::invalid_argument("overlapping mapped regions are ambiguous");
        if (!entry_executable) throw std::invalid_argument("entry must identify an explicitly executable mapped region");
        if (library_initialized && configured_specs != spec_directory)
            throw std::invalid_argument("spec_directory is fixed for the lifetime of this isolated worker");
        stage = "initialize";
        if (!library_initialized) {
            startDecompilerLibrary(std::vector<std::string>{spec_directory});
            configured_specs = spec_directory;
            library_initialized = true;
        }
        BoundedStream diagnostics_buffer(64 * 1024);
        std::ostream diagnostics(&diagnostics_buffer);
        diagnostics.exceptions(std::ios::badbit | std::ios::failbit);
        BoundedStream c_buffer(output_budget);
        std::ostream c_output(&c_buffer);
        c_output.exceptions(std::ios::badbit | std::ios::failbit);
        DocumentStorage storage;
        MemoryArchitecture architecture(target, &diagnostics, std::move(mapped));
        architecture.init(storage);
        const auto space = architecture.getDefaultCodeSpace();
        if (space->getWordSize() != 1 || function_end - 1 > space->getHighest())
            throw LowlevelError("function range exceeds the supported byte-addressed processor space");
        architecture.max_instructions = max_instructions;
        architecture.max_jumptable_size = 4096;
        // Only regions explicitly marked readonly by the caller participate.
        architecture.readonlypropagate = true;
        architecture.flowoptions = FlowInfo::error_outofbounds | FlowInfo::error_unimplemented |
            FlowInfo::error_reinterpreted | FlowInfo::error_toomanyinstructions;
        architecture.setPrintLanguage("c-language");
        Funcdata *function = architecture.symboltab->getGlobalScope()->addFunction(Address(space, entry), "ig5_function")->getFunction();
        stage = "follow-flow";
        // Ghidra's flow implementation takes a bounding end address. The caller
        // always supplies an exclusive end, consistent with its fallthrough bound.
        function->followFlow(Address(space, function_begin), Address(space, function_end));
        if (function->hasBadData() || function->hasUnimplemented())
            throw LowlevelError("function flow contains inaccessible or unimplemented instructions");
        // Upstream fallthrough uses an exclusive end, while an explicit branch
        // comparison also admits the end address. Verify actual lifted instruction
        // starts and consumed lengths before accepting that mixed convention.
        std::set<uint64_t> instruction_addresses;
        for (auto op = function->beginOpAll(); op != function->endOpAll(); ++op) {
            uint64_t address = op->second->getAddr().getOffset();
            if (address < function_begin || address >= function_end)
                throw LowlevelError("lifted instruction is outside the exclusive function bounds");
            instruction_addresses.insert(address);
        }
        for (uint64_t address : instruction_addresses) {
            int4 length = architecture.translate->instructionLength(Address(space, address));
            if (length < 1 || static_cast<uint64_t>(length) > function_end - address)
                throw LowlevelError("lifted instruction crosses the function end");
            bool executable = false;
            for (size_t index = 0; index < region_count; ++index) {
                const auto &region = regions[index];
                if (region.flags & IG5_DEC_EXECUTABLE && region.start <= address &&
                    address - region.start < region.size && static_cast<uint64_t>(length) <= region.size - (address - region.start))
                    executable = true;
            }
            if (!executable) throw LowlevelError("lifted instruction is outside executable mapped bytes");
        }
        stage = "decompile";
        Action *action = architecture.allacts.setCurrent("decompile");
        action->reset(*function);
        int4 changes = action->perform(*function);
        if (changes < 0 || !function->isProcComplete())
            throw LowlevelError("native decompiler action did not complete");
        stage = "print-c";
        architecture.print->setOutputStream(&c_output);
        architecture.print->setMarkup(false);
        architecture.print->setFlat(false);
        architecture.print->docFunction(function);
        c_output.flush();
        if (c_buffer.str().empty()) throw LowlevelError("native C printer returned no function");
        std::string json = "{\"ok\":true,\"engine\":\"IG5 Kernel\",\"core\":\"Ghidra native decompiler\","
            "\"jvmStarted\":false,\"commercialEngineUsed\":false,\"complete\":true,\"entry\":" + escape(hexvalue(entry)) +
            ",\"functionBegin\":" + escape(hexvalue(function_begin)) + ",\"functionEnd\":" + escape(hexvalue(function_end)) +
            ",\"instructionLimit\":" + std::to_string(max_instructions) + ",\"mappedBytes\":" + std::to_string(total) +
            ",\"readBytes\":" + std::to_string(static_cast<OwnedLoadImage *>(architecture.loader)->readCount()) +
            ",\"blocks\":" + std::to_string(function->getBasicBlocks().getSize()) + ",\"code\":" + escape(c_buffer.str()) +
            ",\"diagnostics\":" + escape(diagnostics_buffer.str()) + ",\"optimizerDeadline\":\"external isolated worker\"}";
        if (json.size() > 8 * 1024 * 1024) throw BudgetError("native JSON output budget exceeded");
        return result(json, output, capacity, required, 0);
    } catch (const BudgetError &error) {
        return error_result(error.what(), stage, output, capacity, required, 4, true);
    } catch (const LowlevelError &error) {
        if (error.explain == "Flow exceeded maximum allowable instructions")
            return error_result(error.explain.c_str(), stage, output, capacity, required, 4, true);
        return error_result(error.explain.c_str(), stage, output, capacity, required, 3);
    } catch (const std::invalid_argument &error) {
        return error_result(error.what(), stage, output, capacity, required, 2);
    } catch (const std::bad_alloc &) {
        return error_result("native allocation budget failed", stage, output, capacity, required, 4, true);
    } catch (const std::exception &error) {
        return error_result(error.what(), stage, output, capacity, required, 3);
    } catch (...) {
        return error_result("unknown native decompiler failure", stage, output, capacity, required, 3);
    }
}

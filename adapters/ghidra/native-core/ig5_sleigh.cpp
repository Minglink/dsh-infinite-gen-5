// IG5 adapter. Third-party Sleigh remains under its upstream Apache-2.0 license.
#include "ig5_sleigh.h"
#include "sleigh.hh"
#include "loadimage.hh"
#include "slaformat.hh"
#include <cstring>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace {
using namespace ghidra;
std::mutex decode_mutex;
std::once_flag identifiers;
std::string json_string(const std::string &value) {
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
    std::ostringstream result;
    result << "0x" << std::hex << value;
    return result.str();
}
class BytesImage : public LoadImage {
    uint64_t base;
    const uint8_t *data;
    size_t length;
public:
    BytesImage(uint64_t start, const uint8_t *bytes, size_t size) : LoadImage("ig5-memory"), base(start), data(bytes), length(size) {}
    void loadFill(uint1 *output, int4 size, const Address &address) override {
        // Sleigh looks ahead beyond the last instruction. Padding may aid parsing,
        // but the final consumed instruction length is checked against real bytes.
        for (int4 i = 0; i < size; ++i) {
            uint64_t value = address.getOffset() + i;
            output[i] = value >= base && value - base < length ? data[value - base] : 0;
        }
    }
    std::string getArchType() const override { return "ig5-memory"; }
    void adjustVma(long) override {}
};
class BufferSleigh : public Sleigh {
public:
    BufferSleigh(LoadImage *image, ContextDatabase *context) : Sleigh(image, context) {}
    void load(std::istream &stream) {
        sla::FormatDecode decoder(this);
        decoder.ingestStream(stream);
        decode(decoder);
        DocumentStorage empty;
        initialize(empty); // base already initialized; only creates parsing cache
    }
};
class Assembly : public AssemblyEmit {
public:
    std::string mnemonic, body;
    void dump(const Address &, const std::string &name, const std::string &operands) override { mnemonic = name; body = operands; }
};
std::string varnode(const VarnodeData &node) {
    return "{\"space\":" + json_string(node.space->getName()) + ",\"offset\":" + json_string(hexvalue(node.offset)) + ",\"size\":" + std::to_string(node.size) + "}";
}
class Pcode : public PcodeEmit {
public:
    std::vector<std::string> operations;
    void dump(const Address &, OpCode opcode, VarnodeData *output, VarnodeData *inputs, int4 count) override {
        if (operations.size() >= 4096 || count < 0 || count > 64) throw LowlevelError("p-code output budget exceeded");
        std::string value = "{\"opcode\":" + json_string(get_opname(opcode)) + ",\"output\":" + (output ? varnode(*output) : "null") + ",\"inputs\":[";
        for (int4 i = 0; i < count; ++i) {
            std::string input;
            if (i == 0 && (opcode == CPUI_LOAD || opcode == CPUI_STORE)) {
                // Native Sleigh encodes this operand as an internal AddrSpace*
                // token, never a target constant/address. Do not expose a host
                // pointer or use it in architecture-independent fingerprints.
                const auto space = reinterpret_cast<const AddrSpace *>(inputs[i].offset);
                input = "{\"kind\":\"address-space\",\"space\":" + json_string(space->getName()) + ",\"spaceId\":" + std::to_string(space->getIndex()) + "}";
            } else input = varnode(inputs[i]);
            value += (i ? "," : "") + input;
        }
        operations.push_back(value + "]}");
    }
};
int write_result(const std::string &json, char *output, size_t capacity, size_t *required, int status) {
    *required = json.size() + 1;
    if (!output || capacity < *required) return 1;
    std::memcpy(output, json.c_str(), *required);
    return status;
}
}

extern "C" IG5_SLEIGH_API int ig5_sleigh_decode(
    const uint8_t *sla, size_t sla_size, const uint8_t *code, size_t code_size,
    uint64_t base, const ig5_sleigh_context *context, size_t context_count,
    size_t maximum, char *output, size_t capacity, size_t *required) {
    if (!required) return 2;
    if (!sla || !code || sla_size == 0 || sla_size > 64 * 1024 * 1024 ||
        code_size == 0 || code_size > 1024 * 1024 || maximum == 0 || maximum > 1024 ||
        context_count > 64 || (context_count && !context) ||
        code_size > std::numeric_limits<uint64_t>::max() - base)
        return write_result("{\"ok\":false,\"error\":\"invalid bounded decoder arguments\"}", output, capacity, required, 2);
    std::lock_guard<std::mutex> lock(decode_mutex);
    try {
        std::call_once(identifiers, [] { AttributeId::initialize(); ElementId::initialize(); });
        BytesImage image(base, code, code_size);
        ContextInternal defaults;
        BufferSleigh translator(&image, &defaults);
        std::istringstream specification(std::string(reinterpret_cast<const char *>(sla), sla_size), std::ios::binary);
        translator.load(specification);
        for (size_t i = 0; i < context_count; ++i) {
            if (!context[i].name || std::strlen(context[i].name) > 128) throw LowlevelError("invalid context name");
            defaults.setVariableDefault(context[i].name, context[i].value);
        }
        const auto space = translator.getDefaultCodeSpace();
        if (base > space->getHighest() || code_size - 1 > space->getHighest() - base)
            throw LowlevelError("input range exceeds processor address space");
        size_t offset = 0, count = 0;
        std::string rows;
        std::string failure;
        while (offset < code_size && count < maximum) {
            try {
                Address address(space, base + offset);
                Assembly assembly;
                int4 length = translator.printAssembly(assembly, address);
                if (length <= 0 || static_cast<size_t>(length) > code_size - offset) throw LowlevelError("truncated instruction bytes");
                Pcode pcode;
                if (translator.oneInstruction(pcode, address) != length) throw LowlevelError("instruction length mismatch");
                if (count) rows += ',';
                rows += "{\"ea\":" + json_string(hexvalue(base + offset)) + ",\"size\":" + std::to_string(length) +
                        ",\"mnemonic\":" + json_string(assembly.mnemonic) + ",\"operands\":" + json_string(assembly.body) + ",\"pcode\":[";
                for (size_t i = 0; i < pcode.operations.size(); ++i) rows += (i ? "," : "") + pcode.operations[i];
                rows += "]}";
                if (rows.size() > 16 * 1024 * 1024) throw LowlevelError("response byte budget exceeded");
                offset += length;
                ++count;
            } catch (const LowlevelError &error) { failure = error.explain; break; }
        }
        std::string result = "{\"ok\":" + std::string(failure.empty() ? "true" : "false") +
            ",\"engine\":\"Ghidra Sleigh\",\"representation\":\"raw-pcode\",\"count\":" + std::to_string(count) +
            ",\"consumedBytes\":" + std::to_string(offset) + ",\"truncated\":" + (offset < code_size ? "true" : "false") +
            ",\"error\":" + (failure.empty() ? "null" : json_string(failure)) + ",\"instructions\":[" + rows + "]}";
        return write_result(result, output, capacity, required, failure.empty() ? 0 : 3);
    } catch (const LowlevelError &error) {
        return write_result("{\"ok\":false,\"error\":" + json_string(error.explain) + "}", output, capacity, required, 3);
    } catch (const std::exception &error) {
        return write_result("{\"ok\":false,\"error\":" + json_string(error.what()) + "}", output, capacity, required, 3);
    } catch (...) {
        return write_result("{\"ok\":false,\"error\":\"native decoder exception\"}", output, capacity, required, 3);
    }
}

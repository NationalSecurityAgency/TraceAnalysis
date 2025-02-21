#include <memory>

#include "libdecomp.hh"
#include "sleigh.hh"
#include "loadimage.hh"
#include "sleigh_arch.hh"
#include "inject_sleigh.hh"

//#include "ghidra-lifter/src/lib.rs.h"

namespace rust {
    namespace behavior {
        template <typename Try, typename Fail>
        static void trycatch(Try &&func, Fail &&fail) noexcept try {
            func();
        } catch (std::exception &e) {
            fail(e.what());
        } catch (ghidra::LowlevelError &e) {
            fail(e.explain.c_str());
        } 
    }
}

namespace lifter {

void startDecompilerLibrary(const std::string&, const std::vector<std::string>&);

struct Handle;
struct PcodeOperation;
struct PcodeVar;

class GhidraLifter {
public:
    GhidraLifter(const std::string& archid);
    virtual ~GhidraLifter(void);

    int32_t lift(uint64_t pc, const uint8_t* bytes, const size_t size);
    int32_t instructionLength(uint64_t pc, const uint8_t* bytes, const size_t size);
    void clear(void);
    const std::string& getAssembly(void) const;
    const std::vector<PcodeOperation>& getOperations(void) const;
    const std::vector<PcodeVar>& getVars(void) const;
    int32_t getConstantSpaceId(void) const;
    int32_t getUniqueSpaceId(void) const;
    int32_t getDefaultCodeSpaceId(void) const;
    int32_t getDefaultDataSpaceId(void) const;
    int32_t numSpaces(void) const;
    ghidra::AddrSpace* getSpace(int32_t) const; 
    PcodeVar getRegisterByName(const std::string& nm) const;

private:
    class Architecture : public ghidra::Architecture {
        friend GhidraLifter;

    public:
        Architecture(void);
        virtual ~Architecture(void);

        virtual void printMessage(const std::string& message) const;
        virtual ghidra::Translate* buildTranslator(ghidra::DocumentStorage& store);
        virtual void buildLoader(ghidra::DocumentStorage& store);
        virtual ghidra::PcodeInjectLibrary* buildPcodeInjectLibrary(void);
        virtual void buildTypegrp(ghidra::DocumentStorage& store);
        virtual void buildCoreTypes(ghidra::DocumentStorage& store);
        virtual void buildCommentDB(ghidra::DocumentStorage& store);
        virtual void buildStringManager(ghidra::DocumentStorage& store);
        virtual void buildConstantPool(ghidra::DocumentStorage& store);
        virtual void buildContext(ghidra::DocumentStorage& store);
        virtual void buildSymbols(ghidra::DocumentStorage& store);
        virtual void buildSpecFile(ghidra::DocumentStorage& store);
        virtual void modifySpaces(ghidra::Translate* trans);
        virtual void resolveArchitecture(void);
    private:
        const ghidra::LanguageDescription& getLanguageDescription(void);
    };

    class LoadImage : public ghidra::LoadImage {
        friend GhidraLifter;

    public:
        LoadImage(const std::string& archid);
        virtual ~LoadImage(void);

        virtual void loadFill(ghidra::uint1 *ptr, ghidra::int4 size, const ghidra::Address& addr);
        virtual ghidra::string getArchType(void) const;
        virtual void adjustVma(long adjust);
        
    private:
        ghidra::uintb current_base;
        std::string archid;
        std::vector<ghidra::uint1> buffer;
    };

    class AssemblyEmit : public ghidra::AssemblyEmit {
        friend GhidraLifter;

    public:
        AssemblyEmit(void);
        virtual ~AssemblyEmit(void);

        virtual void dump(
                const ghidra::Address& addr,
                const std::string& mnem,
                const std::string& body);
    private:
        std::string text;
    };

    class PcodeEmit : public ghidra::PcodeEmit {
        friend GhidraLifter;

    public:
        PcodeEmit(void);
        virtual ~PcodeEmit(void);

        virtual void dump(
                const ghidra::Address& addr,
                ghidra::OpCode opc,
                ghidra::VarnodeData* outvar,
                ghidra::VarnodeData* vars,
                ghidra::int4 isize);

    private:
        std::vector<PcodeOperation> operations;
        std::vector<PcodeVar> vars;
    };

    LoadImage* loader(void);
    Architecture arch;
    AssemblyEmit assembly;
    PcodeEmit pcode;
};

// This is a hack. SLEIGH caches disassembly results based solely on the base address of the
// instruction. That is not ideal for a few reasons (e.g. self-modifying code, multiple address
// spaces, etc.), but there does not appear to be an obvious way to disable this.
//
// Most of the fields in the DisassemblyCache are private and cannot be modified directly to clear
// the cache before lifting, so we sub-class the SLEIGH engine and hook each of the functions that
// consult the cache. Prior to their invocation, we request the same cache entry and manually
// invalidate it.
//
// This is not likely to work on architectures with delay slots since they request a number of
// instructions after the baseaddress, and the logic for calculating those addresses may not be
// idempotent.
class SleighNoCache : public ghidra::Sleigh {
public:
    using ghidra::Sleigh::Sleigh;

    virtual ghidra::int4 instructionLength(const ghidra::Address &baseaddr) const;
    virtual ghidra::int4 oneInstruction(
            ghidra::PcodeEmit &emit,
            const ghidra::Address &baseaddr) const;
    virtual ghidra::int4 printAssembly(
            ghidra::AssemblyEmit &emit,
            const ghidra::Address &baseaddr) const;
};

std::unique_ptr<GhidraLifter> new_ghidra_lifter(const Handle& handle, const std::string& archid);

struct PcodeOperation {
    ghidra::OpCode opc;
    bool has_outvar;
    size_t vars;
    size_t size;
};

struct PcodeVar {
    int32_t space_id;
    uint64_t offset;
    uint32_t size;
};

}

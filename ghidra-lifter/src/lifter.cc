#include "ghidra-lifter/include/lifter.h"

#include <iostream>
#include <exception>

namespace lifter {

void startDecompilerLibrary(
        const std::string& sleighhome,
        const std::vector<std::string>& extrapaths) {
    auto s = sleighhome.empty() ? nullptr : sleighhome.c_str();
    ghidra::startDecompilerLibrary(s, extrapaths);
}

std::unique_ptr<GhidraLifter> new_ghidra_lifter(const Handle& handle, const std::string& archid) {
    return std::make_unique<GhidraLifter>(archid);
}

GhidraLifter::GhidraLifter(const std::string& archid) {
    this->arch.loader = new GhidraLifter::LoadImage(archid);
    ghidra::DocumentStorage store;
    this->arch.init(store);
}

GhidraLifter::~GhidraLifter(void) {}

GhidraLifter::LoadImage* GhidraLifter::loader(void) {
    return dynamic_cast<GhidraLifter::LoadImage*>(this->arch.loader);
}

int32_t GhidraLifter::lift(uint64_t pc, const uint8_t* bytes, const size_t size) {
    this->clear();
    this->loader()->buffer.resize(size);
    memcpy(this->loader()->buffer.data(), bytes, size);
    ghidra::Address addr(this->arch.getDefaultCodeSpace(), pc);

    this->arch.translate->printAssembly(this->assembly, addr);
    return this->arch.translate->oneInstruction(this->pcode, addr);
}

int32_t GhidraLifter::instructionLength(uint64_t pc, const uint8_t* bytes, const size_t size) {
    this->clear();
    this->loader()->buffer.resize(size);
    memcpy(this->loader()->buffer.data(), bytes, size);
    ghidra::Address addr(this->arch.getDefaultCodeSpace(), pc);

    return this->arch.translate->instructionLength(addr);
}

PcodeVar GhidraLifter::getRegisterByName(const std::string& nm) const {
    auto varnode = this->arch.translate->getRegister(nm);
    PcodeVar var {
        varnode.space->getIndex(),
        varnode.offset,
        varnode.size
    };
    return var;
}

void GhidraLifter::clear(void) {
    this->loader()->buffer.clear();
    this->assembly.text.clear();
    this->pcode.operations.clear();
    this->pcode.vars.clear();
}

const std::string& GhidraLifter::getAssembly(void) const {
    return this->assembly.text;
}

const std::vector<PcodeOperation>& GhidraLifter::getOperations(void) const {
    return this->pcode.operations;
}

const std::vector<PcodeVar>& GhidraLifter::getVars(void) const {
    return this->pcode.vars;
}

int32_t GhidraLifter::getConstantSpaceId(void) const {
    return this->arch.getConstantSpace()->getIndex();
}

int32_t GhidraLifter::getUniqueSpaceId(void) const {
    return this->arch.getUniqueSpace()->getIndex();
}

int32_t GhidraLifter::getDefaultCodeSpaceId(void) const {
    return this->arch.getDefaultCodeSpace()->getIndex();
}

int32_t GhidraLifter::getDefaultDataSpaceId(void) const {
    return this->arch.getDefaultDataSpace()->getIndex();
}

int32_t GhidraLifter::numSpaces(void) const {
    return this->arch.numSpaces();
}

ghidra::AddrSpace* GhidraLifter::getSpace(int32_t i) const {
    return this->arch.getSpace(i);
}


GhidraLifter::LoadImage::LoadImage(const std::string& archid)
    : ghidra::LoadImage("no-file")
    , archid(archid)
{}

GhidraLifter::LoadImage::~LoadImage(void) {}

void GhidraLifter::LoadImage::loadFill(
        ghidra::uint1 *ptr,
        ghidra::int4 size,
        const ghidra::Address& addr) {

    memset(ptr, 0, size);
    auto count = size > this->buffer.size() ? this->buffer.size() : size;
    memcpy(ptr, this->buffer.data(), count);

}

std::string GhidraLifter::LoadImage::getArchType(void) const {
    return this->archid;
}

void GhidraLifter::LoadImage::adjustVma(long adjust) {}

GhidraLifter::Architecture::Architecture(void) {}
GhidraLifter::Architecture::~Architecture(void) {}

void GhidraLifter::Architecture::printMessage(const std::string& message) const {}

ghidra::Translate* GhidraLifter::Architecture::buildTranslator(ghidra::DocumentStorage& store) {
    return new SleighNoCache(this->loader, this->context);
}

void GhidraLifter::Architecture::buildLoader(ghidra::DocumentStorage& store) {
    // Do nothing, loader is initialized by GhidraLifter
}

ghidra::PcodeInjectLibrary* GhidraLifter::Architecture::buildPcodeInjectLibrary(void) {
    return new ghidra::PcodeInjectLibrarySleigh(this);
}

void GhidraLifter::Architecture::buildTypegrp(ghidra::DocumentStorage& store) {
    this->types = new ghidra::TypeFactory(this);
}

void GhidraLifter::Architecture::buildCoreTypes(ghidra::DocumentStorage& store) {
    const ghidra::Element* el = store.getTag("coretypes");

    if (el != nullptr) {
        ghidra::XmlDecode decoder(this, el);
        this->types->decodeCoreTypes(decoder);
    } else {
        this->types->setCoreType("void", 1, ghidra::TYPE_VOID, false);
        this->types->setCoreType("bool", 1, ghidra::TYPE_BOOL, false);
        this->types->setCoreType("uint1", 1, ghidra::TYPE_UINT, false);
        this->types->setCoreType("uint2", 2, ghidra::TYPE_UINT, false);
        this->types->setCoreType("uint4", 4, ghidra::TYPE_UINT, false);
        this->types->setCoreType("uint8", 8, ghidra::TYPE_UINT, false);
        this->types->setCoreType("int1", 1, ghidra::TYPE_INT, false);
        this->types->setCoreType("int2", 2, ghidra::TYPE_INT, false);
        this->types->setCoreType("int4", 4, ghidra::TYPE_INT, false);
        this->types->setCoreType("int8", 8, ghidra::TYPE_INT, false);
        this->types->setCoreType("float4", 4, ghidra::TYPE_FLOAT, false);
        this->types->setCoreType("float8", 8, ghidra::TYPE_FLOAT, false);
        this->types->setCoreType("float10", 10, ghidra::TYPE_FLOAT, false);
        this->types->setCoreType("float16", 16, ghidra::TYPE_FLOAT, false);
        this->types->setCoreType("xunknown1", 1, ghidra::TYPE_UNKNOWN, false);
        this->types->setCoreType("xunknown2", 2, ghidra::TYPE_UNKNOWN, false);
        this->types->setCoreType("xunknown4", 4, ghidra::TYPE_UNKNOWN, false);
        this->types->setCoreType("xunknown8", 8, ghidra::TYPE_UNKNOWN, false);
        this->types->setCoreType("code", 1, ghidra::TYPE_CODE, false);
        this->types->setCoreType("char", 1, ghidra::TYPE_INT, true);
        this->types->setCoreType("wchar2", 2, ghidra::TYPE_INT, true);
        this->types->setCoreType("wchar4", 4, ghidra::TYPE_INT, true);
        this->types->cacheCoreTypes();
    }
}

void GhidraLifter::Architecture::buildCommentDB(ghidra::DocumentStorage& store) {
    this->commentdb = new ghidra::CommentDatabaseInternal();
}

void GhidraLifter::Architecture::buildStringManager(ghidra::DocumentStorage& store) {
    this->stringManager = new ghidra::StringManagerUnicode(this, 2048);
}

void GhidraLifter::Architecture::buildConstantPool(ghidra::DocumentStorage& store) {
    this->cpool = new ghidra::ConstantPoolInternal();
}

void GhidraLifter::Architecture::buildContext(ghidra::DocumentStorage& store) {
    this->context = new ghidra::ContextInternal();
}

void GhidraLifter::Architecture::buildSymbols(ghidra::DocumentStorage& store) {
    // Do nothing
}
        
const ghidra::LanguageDescription& GhidraLifter::Architecture::getLanguageDescription(void) {
    auto archid = ghidra::SleighArchitecture::normalizeArchitecture(this->archid);
    auto baseid = archid.substr(0, archid.rfind(':'));
    for (const ghidra::LanguageDescription& lang : ghidra::SleighArchitecture::getDescriptions()) {
        if (lang.getId() == baseid)
            return lang;
    }
    throw ghidra::LowlevelError("No sleigh specification for " + baseid);
}

void GhidraLifter::Architecture::buildSpecFile(ghidra::DocumentStorage& store) {
    auto language = this->getLanguageDescription();
    auto compiler = this->archid.substr(this->archid.rfind(':') + 1);
    const ghidra::CompilerTag& compilertag(language.getCompiler(compiler));

    std::string processorfile;
    std::string compilerfile;
    std::string slafile;

    ghidra::SleighArchitecture::specpaths.findFile(processorfile, language.getProcessorSpec());
    ghidra::SleighArchitecture::specpaths.findFile(compilerfile, compilertag.getSpec());
    ghidra::SleighArchitecture::specpaths.findFile(slafile, language.getSlaFile());

    try {
        ghidra::Document* doc = store.openDocument(processorfile);
        store.registerTag(doc->getRoot());
    } catch (ghidra::DecoderError& err) {
        std::ostringstream serr;
        serr << "XML error parsing processor specification: " << processorfile;
        serr << "\n" << err.explain;
        throw ghidra::SleighError(serr.str());
    } catch (ghidra::LowlevelError& err) {
        std::ostringstream serr;
        serr << "Error reading processor specification: " << processorfile;
        serr << "\n" << err.explain;
        throw ghidra::SleighError(serr.str());
    }
    
    try {
        ghidra::Document* doc = store.openDocument(compilerfile);
        store.registerTag(doc->getRoot());
    } catch (ghidra::DecoderError& err) {
        std::ostringstream serr;
        serr << "XML error parsing compiler specification: " << compilerfile;
        serr << "\n" << err.explain;
        throw ghidra::SleighError(serr.str());
    } catch (ghidra::LowlevelError& err) {
        std::ostringstream serr;
        serr << "Error reading compiler specification: " << compilerfile;
        serr << "\n" << err.explain;
        throw ghidra::SleighError(serr.str());
    }
    
    try {
        ghidra::Document* doc = store.openDocument(slafile);
        store.registerTag(doc->getRoot());
    } catch (ghidra::DecoderError& err) {
        std::ostringstream serr;
        serr << "XML error parsing SLEIGH file: " << slafile;
        serr << "\n" << err.explain;
        throw ghidra::SleighError(serr.str());
    } catch (ghidra::LowlevelError& err) {
        std::ostringstream serr;
        serr << "Error reading SLEIGH file: " << slafile;
        serr << "\n" << err.explain;
        throw ghidra::SleighError(serr.str());
    }
}

void GhidraLifter::Architecture::modifySpaces(ghidra::Translate* trans) {
    auto language = this->getLanguageDescription();
    for (int i = 0; i < language.numTruncations(); i += 1) {
        trans->truncateSpace(language.getTruncation(i));
    }
}

void GhidraLifter::Architecture::resolveArchitecture(void) {
    this->archid = this->loader->getArchType();
}

GhidraLifter::AssemblyEmit::AssemblyEmit(void) {}
GhidraLifter::AssemblyEmit::~AssemblyEmit(void) {}

void GhidraLifter::AssemblyEmit::dump(
        const ghidra::Address& addr,
        const std::string& mnem,
        const std::string& body) {

    this->text += mnem;
    this->text += " ";
    this->text += body;

}

GhidraLifter::PcodeEmit::PcodeEmit(void) {}
GhidraLifter::PcodeEmit::~PcodeEmit(void) {}

void GhidraLifter::PcodeEmit::dump(
        const ghidra::Address& addr,
        ghidra::OpCode opc,
        ghidra::VarnodeData* outvar,
        ghidra::VarnodeData* vars,
        ghidra::int4 isize) {

    // SLEIGH uses the first input of a LOAD and STORE operation to indicate which AddrSpace
    // is being loaded from or stored into. It encodes this as a constant whose value is a raw
    // pointer to the given space. This is an inconvenient representation for our code as it
    // "unsafe" operations in Rust to recover the AddrSpace. Instead we will encode the space as
    // an arbitrary variable within the target space.
    if (opc == ghidra::CPUI_LOAD || opc == ghidra::CPUI_STORE) {
        vars[0].space = vars[0].getSpaceFromConst();
        vars[0].offset = 0;
        vars[0].size = 0;
    }

    size_t vars_index = this->vars.size();
    bool has_outvar = outvar != nullptr;
    if (has_outvar) {
        PcodeVar var {
            outvar->space->getIndex(),
            outvar->offset,
            outvar->size
        };
        this->vars.push_back(var);
    }
    for (size_t i = 0; i < isize; i++) {
        PcodeVar var {
            vars[i].space->getIndex(),
            vars[i].offset,
            vars[i].size
        };
        this->vars.push_back(var);
    }
    PcodeOperation op = {
        opc,
        has_outvar,
        vars_index,
        (has_outvar ? (size_t)isize + 1 : (size_t)isize)
    };
    this->operations.push_back(op);

}

ghidra::int4 SleighNoCache::instructionLength(const ghidra::Address &baseaddr) const {
    auto pos = obtainContext(baseaddr, ghidra::ParserContext::disassembly);
    pos->setParserState(ghidra::ParserContext::uninitialized);
    return ghidra::Sleigh::instructionLength(baseaddr);
}

ghidra::int4 SleighNoCache::oneInstruction(
        ghidra::PcodeEmit &emit,
        const ghidra::Address &baseaddr) const
{
    auto pos = obtainContext(baseaddr, ghidra::ParserContext::pcode);
    pos->setParserState(ghidra::ParserContext::uninitialized);
    return ghidra::Sleigh::oneInstruction(emit, baseaddr);
}

ghidra::int4 SleighNoCache::printAssembly(
        ghidra::AssemblyEmit &emit,
        const ghidra::Address &baseaddr) const
{
    auto pos = obtainContext(baseaddr, ghidra::ParserContext::disassembly);
    pos->setParserState(ghidra::ParserContext::uninitialized);
    return ghidra::Sleigh::printAssembly(emit, baseaddr);
}

}

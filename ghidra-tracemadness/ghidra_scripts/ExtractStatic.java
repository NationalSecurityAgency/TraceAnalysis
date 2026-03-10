import ghidra.app.script.GhidraScript;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.jung.JungToGDirectedGraphAdapter;
import ghidra.graph.GEdge;
import ghidra.graph.GVertex;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangFunction;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonWriter;

import edu.uci.ics.jung.graph.DirectedSparseGraph;

import java.io.FileWriter;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

public class ExtractStatic extends GhidraScript {

    private GDirectedGraph getBBGDirectedGraphForFunction(Function f, List<CodeBlockVertex> V) throws Exception {
	DirectedSparseGraph<CodeBlockVertex, CodeBlockEdge> dg = new DirectedSparseGraph<>();
	CodeBlockModel blockModel = new BasicBlockModel(currentProgram);
	AddressSetView addrSet = f.getBody();
	CodeBlockIterator blockModelIter = blockModel.getCodeBlocksContaining(addrSet, monitor);
	while(blockModelIter.hasNext()) {
	    CodeBlock bb = blockModelIter.next();
	    CodeBlockVertex v = new CodeBlockVertex(bb);
	    V.add(v);
	}

	Map<CodeBlock, CodeBlockVertex> bToV = new HashMap<>();
	for(CodeBlockVertex v : V) {
	    dg.addVertex(v);
	    bToV.put(v.getCodeBlock(), v);
	}
	
	for(CodeBlockVertex sv : V) {
	    CodeBlock block = sv.getCodeBlock();
	    CodeBlockReferenceIterator dsts = block.getDestinations(monitor);
	    while(dsts.hasNext()) {
		CodeBlockReference ref = dsts.next();
		FlowType ft = ref.getFlowType();
		if(ft.isJump() || ft.isConditional() || ft.isFallthrough()) {
		    CodeBlock dst = ref.getDestinationBlock();
		    CodeBlockVertex ev = bToV.get(dst);
		    if(ev == null) continue;
		    dg.addEdge(new CodeBlockEdge(sv, ev), sv, ev);
		}
	    }
	}
	GDirectedGraph<CodeBlockVertex, CodeBlockEdge> gdg = null;
	try {
	    gdg = new JungToGDirectedGraphAdapter<>(dg);
	} catch (Exception e) {
	    return null;
	}
	
	return gdg;
    }

    private Map<CodeBlockVertex, Set<CodeBlockVertex>> getCDG(GDirectedGraph<CodeBlockVertex, CodeBlockEdge> dg, List<CodeBlockVertex> V) throws Exception {
	Map<CodeBlockVertex, Set<CodeBlockVertex>> PDOM = new HashMap<>();
	Map<CodeBlockVertex, Set<CodeBlockVertex>> CDG = new HashMap<>();
	
	for(CodeBlockVertex v : V) {
	    Set<CodeBlockVertex> PDOMv = new HashSet<CodeBlockVertex>();
	    try {
		PDOMv = GraphAlgorithms.findPostDominance(dg, v, monitor);
	    } catch(Exception e) {
		e.printStackTrace();
	    }
	    
	    PDOM.put(v, PDOMv);
	}
	for(CodeBlockVertex v : V) {
	    Set<CodeBlockVertex> CDGv = new HashSet<>();
	    for(CodeBlockVertex n : V) {
		if(v.equals(n)) continue;
		Collection<CodeBlockVertex> nSuccs = dg.getSuccessors(n);
		if(nSuccs.size() < 2) continue;
		boolean aSuccInPDOM = false;
		boolean aSuccNotInPDOM = false;
		for(CodeBlockVertex s : nSuccs) {
		    if(!aSuccInPDOM && PDOM.get(v).contains(s)) {
			aSuccInPDOM = true;
			continue;
		    }
		    if(!aSuccNotInPDOM && !PDOM.get(v).contains(s)) {
			aSuccNotInPDOM = true;
			continue;
		    }
		}
		if(aSuccInPDOM && aSuccNotInPDOM) CDGv.add(n);
	    }
	    CDG.put(v, CDGv);
	}
	return CDG;
    }
    
    @Override
    protected void run() throws Exception {
	String[] args = getScriptArgs();
	String outpath = "/tmp";
	if(args.length > 0) {
	    outpath = args[0];
	}
	List<Map<String, Object>> functions = new ArrayList<>();
	List<Map<String, Object>> calls = new ArrayList<>();
	List<Map<String, Object>> blockof = new ArrayList<>();
	List<Map<String, Object>> blocks = new ArrayList<>();
	List<Map<String, Object>> callingconv = new ArrayList<>();
	List<Map<String, Object>> successors = new ArrayList<>();
	List<Map<String, Object>> decomps = new ArrayList<>();
	List<Map<String, Object>> decompTokens = new ArrayList<>();
	
	
	long progId = currentProgram.getUniqueProgramID();
	String module = currentProgram.getDomainFile().getPathname();
	
	List<Map<String, Object>> cdg = new ArrayList<>();

	BasicBlockModel blockModel = new BasicBlockModel(currentProgram);

	DecompInterface decomp = new DecompInterface();
	if (!decomp.openProgram(currentProgram)) return;
	
	FunctionManager mgr = currentProgram.getFunctionManager();
	for(Function f : mgr.getFunctions(true)) {
	    long fnaddr = f.getEntryPoint().getOffset();
	    long low = f.getBody().getMinAddress().getOffset();
	    long hi = f.getBody().getMaxAddress().getOffset();
	    Map<String, Object> fnEntry = new HashMap<>();
	    fnEntry.put("_key",String.format("%d_%d",progId,fnaddr));
	    fnEntry.put("namespace",f.getParentNamespace().getName());
	    fnEntry.put("name",f.getName());
	    fnEntry.put("addr",fnaddr);
	    fnEntry.put("start",low);
	    fnEntry.put("end",hi);
	    fnEntry.put("module",module);
	    functions.add(fnEntry);

	    DecompileResults decompRes = decomp.decompileFunction(f, 10, null);
	    if(decompRes.decompileCompleted()) {
		DecompiledFunction df = decompRes.getDecompiledFunction();
		String signature = df.getSignature();
		String body = df.getC();
		
		Map<String, Object> decompEntry = new HashMap<>();
		decompEntry.put("fnmodule",module);
		decompEntry.put("fnaddr",fnaddr);
		decompEntry.put("signature",signature);
		decompEntry.put("body",body);
		decomps.add(decompEntry);

		ClangTokenGroup tokenGroup = decompRes.getCCodeMarkup();
		java.util.Iterator<ClangToken> itr = tokenGroup.tokenIterator(true);
		while(itr.hasNext()) {
		    ClangToken t = itr.next();
		    ClangLine line = t.getLineParent();
		    String token_txt = t.getText();
		    long token_len = token_txt.length();
		    if (line == null) continue;
		    if (t.getMaxAddress() == null || t.getMinAddress() == null) continue;
		    
		    long token_idx = line.indexOfToken(t);
		    long token_pos = 0L;
		    for(int ti = 0; ti < token_idx; ti++) {
			token_pos += line.getToken(ti).getText().length();
		    }
		    long token_line = line.getLineNumber();
		    long token_min_addr = t.getMinAddress().getOffset();
		    long token_max_addr = t.getMaxAddress().getOffset();
		    Map<String, Object> tokenEntry = new HashMap<>();
		    tokenEntry.put("fnmodule",module);
		    tokenEntry.put("fnaddr",fnaddr);
		    tokenEntry.put("text",token_txt);
		    tokenEntry.put("len",token_len);
		    tokenEntry.put("linepos",token_pos);
		    tokenEntry.put("linenum",token_line);
		    tokenEntry.put("minaddr",token_min_addr);
		    tokenEntry.put("maxaddr",token_max_addr);
		    decompTokens.add(tokenEntry);
		}
		
		HighFunction hf = decompRes.getHighFunction();
		if(hf != null) {
		    FunctionPrototype fnProto = hf.getFunctionPrototype();
		    int sp = hf.getCompilerSpec().getStackPointer().getOffset();
		    for(int i = 0; i < fnProto.getNumParams(); i++) {
			Map<String, Object> callconvEntry = new HashMap<>();
			VariableStorage argStorage = fnProto.getParam(i).getStorage();
			if(argStorage.isStackStorage()) {
			    int offset = argStorage.getStackOffset();
			    int size = argStorage.size();
			    callconvEntry.put("fnmodule",module);
			    callconvEntry.put("fnaddr",fnaddr);
			    callconvEntry.put("argnum",i+1);
			    callconvEntry.put("storage_type","stack");
			    callconvEntry.put("storage_offset",offset);
			    callconvEntry.put("storage_size",size);
			    callingconv.add(callconvEntry);
			} else if (argStorage.isRegisterStorage()) {
			    int offset = argStorage.getRegister().getOffset();
			    int size = argStorage.size();
			    callconvEntry.put("fnmodule",module);
			    callconvEntry.put("fnaddr",fnaddr);
			    callconvEntry.put("argnum",i+1);
			    callconvEntry.put("storage_type","reg");
			    callconvEntry.put("storage_offset",offset);
			    callconvEntry.put("storage_size",size);
			    callingconv.add(callconvEntry);
			}
			
		    }
		    VariableStorage retStorage = fnProto.getReturnStorage();
		    Map<String, Object> callconvEntry = new HashMap<>();
		    if(retStorage.isStackStorage()) {
			int offset = retStorage.getStackOffset();
			int size = retStorage.size();
			callconvEntry.put("fnmodule",module);
			callconvEntry.put("fnaddr",fnaddr);
			callconvEntry.put("argnum",0);
			callconvEntry.put("storage_type","stack");
			callconvEntry.put("storage_offset",offset);
			callconvEntry.put("storage_size",size);
			callingconv.add(callconvEntry);
		    } else if (retStorage.isRegisterStorage()) {
			int offset = retStorage.getRegister().getOffset();
			int size = retStorage.size();
			callconvEntry.put("fnmodule",module);
			callconvEntry.put("fnaddr",fnaddr);
			callconvEntry.put("argnum",0);
			callconvEntry.put("storage_type","reg");
			callconvEntry.put("storage_offset",offset);
			callconvEntry.put("storage_size",size);
			callingconv.add(callconvEntry);
		    }
		}
	    }
	    
	    // Get the calls to the function
	    Reference[] refs = getReferencesTo(f.getEntryPoint());
	    for(int i = 0; i < refs.length; i++) {
		Function xf = getFunctionContaining(refs[i].getFromAddress());
		if(xf == null) continue;
		long xfaddr = xf.getEntryPoint().getOffset();
		Map<String, Object> call = new HashMap<>();
		call.put("_from",String.format("functions/%d_%d", progId, xfaddr));
		call.put("_to",String.format("functions/%d_%d", progId, fnaddr));
		call.put("callsite",String.format("%d",refs[i].getFromAddress().getOffset()));
		calls.add(call);
	    }

	    // Get the basic blocks within the function
	    
	    CodeBlockIterator codeBlocks = blockModel.getCodeBlocksContaining(f.getBody(), monitor);
	    while(codeBlocks.hasNext()) {
		CodeBlock b = codeBlocks.next();
		long baddr = b.getMinAddress().getOffset();
		long bend = b.getMaxAddress().getOffset();
		Map<String, Object> bEntry = new HashMap<>();
		bEntry.put("_key", String.format("%d_%d", progId, baddr));
		bEntry.put("addr", baddr);
		bEntry.put("end", bend);
		bEntry.put("module",module);
		blocks.add(bEntry);
		
		Map<String, Object> blockOfEntry = new HashMap<>();
		blockOfEntry.put("_from", String.format("blocks/%d_%d", progId, baddr));
		blockOfEntry.put("_to", String.format("functions/%d_%d", progId, fnaddr));
		blockof.add(blockOfEntry);

		// Finally, get the successors of the basic block
		CodeBlockReferenceIterator succs = b.getDestinations(monitor);
		while(succs.hasNext()) {
		    CodeBlockReference bref = succs.next();
		    FlowType ft = bref.getFlowType();
		    if(ft.isJump() || ft.isConditional() || ft.isFallthrough()) {
			Map<String, Object> succEntry = new HashMap<>();
			succEntry.put("_from",String.format("blocks/%d_%d", progId, bref.getDestinationAddress().getOffset()));
			succEntry.put("_to",String.format("blocks/%d_%d", progId, baddr));
			successors.add(succEntry);
		    }
		}
	    }
	    
	    
	    List<CodeBlockVertex> V = new ArrayList<>();
	    GDirectedGraph<CodeBlockVertex, CodeBlockEdge> dg = getBBGDirectedGraphForFunction(f, V);
	    if(dg == null || V.size() == 0) continue;
	    
	    Map<CodeBlockVertex, Set<CodeBlockVertex>> cdgmap = getCDG(dg, V);
	    for(CodeBlockVertex v : cdgmap.keySet()) {
		Long src = v.getCodeBlock().getFirstStartAddress().getOffset();
		for(CodeBlockVertex n : cdgmap.get(v)) {
		    long dst = n.getCodeBlock().getFirstStartAddress().getOffset();
		    Map<String, Object> entry = new HashMap<>();
		    entry.put("_key", String.format("%d_%d_%d_%d", progId, fnaddr, src, dst));
		    entry.put("_from", String.format("blocks/%d_%d", progId, src));
		    entry.put("_to", String.format("blocks/%d_%d", progId, dst));
		    cdg.add(entry);
		}
	    }
	}
	decomp.dispose();
	try {
	    exportJSON(outpath, "blocks.jsonl", blocks);
	    exportJSON(outpath, "functions.jsonl", functions);
	    exportJSON(outpath, "cdg.jsonl", cdg);
	    exportJSON(outpath, "blockof.jsonl", blockof);
	    exportJSON(outpath, "successorof.jsonl", successors);
	    exportJSON(outpath, "callerof.jsonl", calls);
	    
	    exportJSON(outpath, "decomptokens.jsonl", decompTokens);
	    exportJSON(outpath, "decomps.jsonl", decomps);
	    exportJSON(outpath, "callingconvs.jsonl", callingconv);
	} catch(Exception e) {
	    throw(e);
	}
    }

    private void exportJSON(String path, String filename, List<Map<String, Object>> data) throws Exception {
	
	try {
	    Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	    FileWriter outputFile = new FileWriter(String.format("%s/%s", path, filename), false);
	    for(Map<String, Object> m : data) {
		outputFile.write(gson.toJson(m) + "\n");
	    }
	    outputFile.flush();
	    outputFile.close();
	} catch(Exception e) {
	    throw(e);
	}
    }
}

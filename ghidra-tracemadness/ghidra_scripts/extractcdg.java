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
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.block.graph.CodeBlockEdge;

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

public class extractcdg extends GhidraScript {

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
    
    private void exportCDG() throws Exception {
	JsonObject cdgVertexList = new JsonObject();
	Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	FunctionManager mgr = currentProgram.getFunctionManager();
	FunctionIterator fns = mgr.getFunctions(true);
	for(Function f : fns) {
	    List<CodeBlockVertex> V = new ArrayList<>();
	    GDirectedGraph<CodeBlockVertex, CodeBlockEdge> dg = getBBGDirectedGraphForFunction(f, V);
	    if(dg == null || V.size() == 0) continue;
	    Map<CodeBlockVertex, Set<CodeBlockVertex>> cdg = getCDG(dg, V);
	    Map<String, Set<String>> addrCDG = new HashMap<>();
	    for(CodeBlockVertex v : cdg.keySet()) {
		Set<String> cdgv = new HashSet<>();
		for(CodeBlockVertex n : cdg.get(v)) {
		    long addr = n.getCodeBlock().getFirstStartAddress().getOffset();
		    cdgv.add(Long.toString(addr));
		}
		Long addr = v.getCodeBlock().getFirstStartAddress().getOffset();
		addrCDG.put(Long.toString(addr), cdgv);
	    }
	    long addr = f.getEntryPoint().getOffset();

	    JsonObject outputJson = new JsonObject();
	    outputJson.addProperty(Long.toString(addr), gson.toJson(addrCDG));
	    try {
		FileWriter outputFile = new FileWriter("/tmp/cdg.json", true);
		gson.toJson(outputJson, outputFile);
		outputFile.flush();
		outputFile.close();
	    } catch(Exception e) {
		throw(e);
	    }
	}
    }
    @Override
    protected void run() throws Exception {
	long progId = currentProgram.getUniqueProgramID();
	Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	List<Map<String, String>> ans = new ArrayList<>();
	
	FunctionManager mgr = currentProgram.getFunctionManager();
	//Function f = mgr.getFunctionContaining(currentAddress);
	for(Function f : mgr.getFunctions(true)) {
	    System.out.println(f.getName());
	    long fnaddr = f.getEntryPoint().getOffset();
	    long low = f.getBody().getMinAddress().getOffset();
	    long hi = f.getBody().getMaxAddress().getOffset();
	    Map<String, String> fnEntry = new HashMap<>();
	    fnEntry.put("_key",String.format("%d_%d",progId,fnaddr));
	    fnEntry.put("namespace",f.getParentNamespace().getName());
	    fnEntry.put("name",f.getName());
	    fnEntry.put("addr",String.format("%d",addr));
	    fnEntry.put("start",String.format("%d",low));
	    fnEntry.put("end",String.format("%d",hi));
	    
	    

	    
	    
	    List<CodeBlockVertex> V = new ArrayList<>();
	    GDirectedGraph<CodeBlockVertex, CodeBlockEdge> dg = getBBGDirectedGraphForFunction(f, V);
	    if(dg == null || V.size() == 0) continue;
	    /*System.out.println(dg);
	      for(CodeBlockEdge e : dg.getEdges()) {
	      String start = "none";
	      String end = "none";
	      if(e.getStart().getCodeBlock() != null) start = String.format("0x%x", e.getStart().getCodeBlock().getStartAddresses()[0].getOffset());
	      if(e.getEnd().getCodeBlock() != null) end = String.format("0x%x", e.getEnd().getCodeBlock().getStartAddresses()[0].getOffset());
	      System.out.printf("E %s -> %s\n",start, end);
	      }*/
	    
	    Map<CodeBlockVertex, Set<CodeBlockVertex>> cdg = getCDG(dg, V);
	    for(CodeBlockVertex v : cdg.keySet()) {
		Long src = v.getCodeBlock().getFirstStartAddress().getOffset();
		for(CodeBlockVertex n : cdg.get(v)) {
		    long dst = n.getCodeBlock().getFirstStartAddress().getOffset();
		    Map<String, String> entry = new HashMap<>();
		    entry.put("_key", String.format("%d_%d_%d_%d", progId, fnaddr, src, dst));
		    entry.put("_from", String.format("blocks/%d_%d", progId, src));
		    entry.put("_to", String.format("blocks/%d_%d", progId, dst));
		    ans.add(entry);
		}
	    }
	}
	try {
	    FileWriter outputFile = new FileWriter("/tmp/cdg.jsonl", false);
	    for(Map<String, String> m : ans) {
		outputFile.write(gson.toJson(m) + "\n");
	    }
	    outputFile.flush();
	    outputFile.close();
	} catch(Exception e) {
	    throw(e);
	}
    }
}

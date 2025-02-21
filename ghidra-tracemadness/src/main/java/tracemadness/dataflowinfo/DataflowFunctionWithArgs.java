package tracemadness.dataflowinfo;

import java.math.BigInteger;
import java.util.ArrayList;

import org.json.JSONObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.util.ProgramLocation;
import tracemadness.MadnessPlugin;

public class DataflowFunctionWithArgs extends DataflowTime {
	
	public Long pc;
	public Long endtick;
	public Long index;
	public Long endindex;
	public BigInteger retval;
	public Long retdep;
	public Long callsite;
	public Long calltick;
	public String disas;
	public String name;
	public ArrayList<Long> argdeps;
	public ArrayList<BigInteger> argvals;
	public int width;
	public DataflowFunctionWithArgs(JSONObject row, MadnessPlugin plugin) throws Exception {
		this.type = FUNCTIONRUN;
		JSONObject stackvals = null;
		JSONObject stackdeps = null;
		JSONObject regvals = null;
		JSONObject regdeps = null;
		
		index = row.getLong("startindex");
		//endindex = row.getLong("endindex");
		tick = row.getLong("starttick");
		//endtick = row.getLong("endtick");
		pc = row.getLong("pc");
		stackvals = row.getJSONObject("stackvals");
		stackdeps = row.getJSONObject("stackdeps");
		regvals = row.getJSONObject("regvals");
		regdeps = row.getJSONObject("regdeps");
		if(row.has("retdep") && !row.isNull("retdep") && row.has("retval") && !row.isNull("retval")) {
			retdep = row.getLong("retdep");
			retval = row.getBigInteger("retval");
		}
		callsite = row.getLong("callsite");

		Address addr = MadnessPlugin.flatApi.toAddr(Long.toHexString(pc));
		try {
			//FunctionManager f = MadnessPlugin.program.getFunctionManager();
			Function fn = plugin.getFunctionContaining(addr);
			//Function fnr = f.getReferencedFunction(addr);
			//SymbolTable s = MadnessPlugin.program.getSymbolTable();
			if (fn != null) {
				name = fn.getName();
			}/* else if (fnr != null) {
				name = fnr.getName();
				fn = fnr;
			} else if (s.getSymbols(addr).length > 0) {
				for (Symbol sss : s.getSymbols(addr)) {
					name = name + sss.getName();
				}
			}*/ else {
				name = "fun_" + addr;
			}
			if(fn != null) {
				HighFunction highFunc;
				if(plugin.decompCache.containsKey(addr)) {
					highFunc = plugin.decompCache.get(addr);
				} else {
					ProgramLocation loc = plugin.getProgramLocation(addr, false);
					if(plugin.decomp.getProgram() != loc.getProgram()) {
						plugin.decomp.openProgram(loc.getProgram());
					}
					highFunc = plugin.decomp.decompileFunction(fn, 5, null).getHighFunction();
					if(highFunc == null) return;
					plugin.decompCache.put(addr, highFunc);
				}
				int params = highFunc.getFunctionPrototype().getNumParams();
				argdeps = new ArrayList<>(params);
				argvals = new ArrayList<>(params);
				
				for(int i = 0; i < params; i++) {
					argdeps.add(null);
					argvals.add(null);
					HighSymbol param = highFunc.getFunctionPrototype().getParam(i);
					VariableStorage storage = param.getStorage();
					if(storage.isStackStorage()) {
						long offset = storage.getStackOffset();
						String offstr = String.format("%d", offset);
						if(stackvals != null && stackvals.has(offstr) && !stackvals.isNull(offstr)) {
							argvals.set(i, stackvals.getBigInteger(offstr));
						} else argvals.set(i, null);
						if(stackdeps != null && stackdeps.has(offstr) && !stackdeps.isNull(offstr)) {
							argdeps.set(i, stackdeps.getBigInteger(offstr).longValue());
						} else argdeps.set(i, null);
					} else if(storage.isRegisterStorage() ) {
						long a = storage.getRegister().getAddress().getOffset();
						String offstr = String.format("%d", a);
						if(regvals != null && regvals.has(offstr) && !regvals.isNull(offstr)) {
							argvals.set(i, regvals.getBigInteger(offstr));
						} else argvals.set(i, null);
						if(regdeps != null && regdeps.has(offstr) && !regdeps.isNull(offstr)) {
							argdeps.set(i, regdeps.getBigInteger(offstr).longValue());
						} else argdeps.set(i, null);
					}
				}
			}
		} catch (NullPointerException npe) {
			MadnessPlugin.LOG.error(npe);
			MadnessPlugin.LOG.error("Row in trouble: " + row);
			throw (npe);
		}
	}
	public String toString() {
		String args = "";
		for(int i = 0; i < this.argvals.size(); i++) {
			BigInteger a = this.argvals.get(i);
			if(a == null) {
				args = args + "?";
			} else {
				args = args + "0x" + a.toString(16);
			}
			if(i < this.argvals.size()-1) {
				args = args + ", ";
			}
		}
		return String.format("%d %s(%s)", this.tick, this.name, args);
	}
}

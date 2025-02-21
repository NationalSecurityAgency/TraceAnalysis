package tracemadness.timelisting;

import java.awt.Dimension;
import java.awt.FontMetrics;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
//import ghidra.program.model.listing.VariableFilter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramLocation;
import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;
import tracemadness.dataflowinfo.DataflowEffect;
import tracemadness.dataflowinfo.DataflowFunctionWithArgs;
import tracemadness.dataflowinfo.DataflowInstructionWithEffects;
import tracemadness.dataflowinfo.DataflowTime;
import tracemadness.listingfield.SpacetimeOperationField;
//import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.FunctionManager;

import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import docking.widgets.fieldpanel.support.*;

/**
 * This class loads a time-ordered listing which can be:
 *   - a time-window (instructions from tick A to tick B)
 *   - a slice (instructions using or used by an effect)
 *   - an address (instances of a PC being run) 
 * 
 * Supports displaying relevant syscallruns, functionruns, and instructionruns.
 * 
 */

@SuppressWarnings("serial")
public class TimeListingLayoutModel implements LayoutModel, MadnessQueryResultListener {

	public MadnessPlugin plugin;
	private FontMetrics fontMetrics;
	private TestHighlightFactory hlFactory; 
	private TimeListingView view;
	private List<DataflowInstructionWithEffects> instructions;
	private List<DataflowFunctionWithArgs> functions;
	private Map<BigInteger, Layout> layoutCache;
	private Map<BigInteger, Long> indexToAddress;
	private Map<BigInteger, Long> indexToTick;
	private Map<Long, BigInteger> tickToIndex;
	private boolean displayInstructions;
	private boolean displayFunctions;
	private DecompInterface decomp;
	private ArrayList<LayoutModelListener> modelListeners;
	HashMap<Address, HighFunction> decompCache;
	private TimeListingProvider provider;
	
	public TimeListingLayoutModel(MadnessPlugin plugin, TimeListingProvider provider, TimeListingView view, FontMetrics fontMetrics, DecompInterface decomp, HashMap<Address, HighFunction> decompCache, boolean displayFunctions, boolean displayInstructions) {
		this.plugin = plugin;
		this.provider = provider;
		this.view = view;
		this.displayInstructions = displayInstructions;
		this.displayFunctions = displayFunctions;
		this.decomp = decomp;
		this.decompCache = decompCache;
		// TODO get the font from Ghidra
		this.fontMetrics = fontMetrics;
		this.hlFactory = new TestHighlightFactory();
		this.hlFactory.resetHighlight();
		this.modelListeners = new ArrayList<>();
	}

	public void addHighlight(Long idx, Long dist) {
		this.hlFactory.addHighlight(idx, dist);
	}
	public void setHighlightOrigin(Long idx) {
		this.hlFactory.setOrigin(idx);
	}
	public void clearHighlight() {
		this.hlFactory.resetHighlight();
	}
	
	private String functionRelativeAddressString(Address addr) {
		ProgramLocation a = plugin.getProgramLocation(addr, false);
		if(a == null) return "<unknown>";
		FunctionManager f = a.getProgram().getFunctionManager();
		Function fn = f.getFunctionContaining(a.getAddress());
		Function fnr = f.getReferencedFunction(a.getAddress());

		if (fn != null) {
			String fnString = fn.getName();
			Address fnAddress = fn.getEntryPoint();
			Long offset = a.getAddress().getOffset() - fnAddress.getOffset();
			fnString = fn.getName() + " + " + "0x" + Long.toHexString(offset);
			return fnString;
		} else if (fnr != null) {
			return fnr.getName();
		}
		return "<unknown>";
	}
	
	public Long getTick(BigInteger index) {
		if(this.indexToTick == null) {
			return 1L;
		}
		if(this.indexToTick.containsKey(index)) {
			return this.indexToTick.get(index);
		}
		return null;
	}

	public BigInteger getTickIndex(Long tick) {
		if(this.tickToIndex.containsKey(tick)) {
			return this.tickToIndex.get(tick);
		}
		return null;
	}

	
	
	public void loadInstructions()  {
		String[] params = { view.toAQLString(), "", String.format("%d", this.plugin.getCurrentProgram().getLanguage().getDefaultSpace().getAddressableUnitSize())};
		this.instructions = new ArrayList<>();
		this.functions = new ArrayList<>();

		try {
			plugin.runQuery("instrace", params, this, "instrace");
		} catch(Exception e) {
			e.printStackTrace();
			return;
		}
	}
	
	public void reloadModel() {
		this.layoutCache = new HashMap<>();
		this.indexToAddress = new HashMap<>();
		this.indexToTick = new HashMap<>();
		this.tickToIndex = new HashMap<>();
		List<DataflowTime> events = new ArrayList<DataflowTime>();
		events.addAll(this.instructions);
		events.addAll(this.functions);
		Collections.sort(events);
		BigInteger index = BigInteger.ZERO;
		for(int i = 0; i < events.size(); i++) {
			DataflowTime dt = events.get(i);

			switch((int)dt.type) {
			case DataflowTime.INSTRUCTIONRUN:
				DataflowInstructionWithEffects ins = (DataflowInstructionWithEffects) dt;
				this.layoutCache.put(index, getLayoutForInstruction(ins));
				this.indexToAddress.put(index, ins.pc);
				this.indexToTick.put(index, ins.tick);
				this.tickToIndex.put(ins.tick, index);
				index = index.add(BigInteger.ONE);
				break;
			case DataflowTime.FUNCTIONRUN:
				break;
			case DataflowTime.SYSCALLRUN:
				break; // TODO handle syscalls
			}
		}
	}
	
	public Long getPCForIndex(BigInteger index) {
		if(this.indexToAddress.containsKey(index)) {
			return this.indexToAddress.get(index);
		}
		return null;
	}
	
	@Override
	public boolean isUniform() {
		// All rows are one line in height
		return true;
	}

	@Override
	public Dimension getPreferredViewSize() {
		return new Dimension(TimeListingSettings.MAX_WIDTH, 500);
	}

	@Override
	public BigInteger getNumIndexes() {
		if(this.indexToTick == null) return BigInteger.ZERO;
		return BigInteger.valueOf(this.indexToTick.size());
	}

	
	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		if(this.indexToTick == null) {
			return null;
		}
		if(index.longValue() >= this.indexToTick.size()) return null;
		if(index.longValue() <= -1) return null;
		return index.add(new BigInteger("1"));
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		if(this.indexToTick == null) {
			return null;
		}
		if(index.longValue() >= this.indexToTick.size()+1) return null;
		if(index.longValue() <= 0) return null;
		return index.add(new BigInteger("-1"));
	}

	@Override
	public Layout getLayout(BigInteger index) {
		if(this.layoutCache == null) {
			return null;
		}
		if(this.layoutCache.containsKey(index)) {
			return this.layoutCache.get(index);
		}
		return null;
	}

	public ArrayList<Field> getLayoutForFunction(DataflowFunctionWithArgs fn, int start) {
		Address addr = MadnessPlugin.flatApi.toAddr(Long.toHexString(fn.pc));
		String fnOffsetStr = functionRelativeAddressString(addr);
		if(fnOffsetStr == null) fnOffsetStr = "<UNKNOWN>";
		int x = start;
		int w = 0;
		int width = fontMetrics.charsWidth(fn.name.toCharArray(), 0, fn.name.length()) + TimeListingSettings.PAD_WIDTH;
		TimeListingTextField fnNameField = new TimeListingTextField(fn.tick, fn.pc, fn.name, x, width, fontMetrics, this.hlFactory);
		x += width;
		width = fontMetrics.charsWidth(new char[]{'('}, 0, 1);
		TimeListingTextField openParenField = new TimeListingTextField(fn.tick, fn.pc, "(", x, width, fontMetrics, this.hlFactory);
		x += width;
		
		ArrayList<Field> fields = new ArrayList<>();
		fields.add(fnNameField);
		fields.add(openParenField);
		if(fn.argdeps != null && fn.argvals != null) {
			for(int i = 0; i < fn.argdeps.size(); i++) {
				if(i >= fn.argvals.size()) break;
				Long argdep = fn.argdeps.get(i);
				BigInteger argval = fn.argvals.get(i);
				if(argdep == null || argval == null) break;
				
				String display = String.format("0x%x", argval);
				width = fontMetrics.charsWidth(display.toCharArray(), 0, display.length());
				fields.add(new TimeListingOperationField(argdep, null, argval, fn.tick, fn.pc, false, display, "Argument value " + display,x, width, fontMetrics, this.hlFactory));
				x += width;
				if(i < fn.argdeps.size() - 1 && i < fn.argvals.size() - 1 && fn.argdeps.get(i+1) != null && fn.argvals.get(i+1) != null) {
					width = fontMetrics.charsWidth(new char[]{',',' '}, 0, 2);
					fields.add(new TimeListingTextField(fn.tick, fn.pc, ",", x, width, fontMetrics, this.hlFactory));
					x += width;
				}
			}
		} else {
			width = fontMetrics.charsWidth(new char[]{'.','.','.'}, 0, 3);
			TimeListingTextField unknownArgsParenField = new TimeListingTextField(fn.tick, fn.pc, "...", x, width, fontMetrics, this.hlFactory);
			x += width;
			fields.add(unknownArgsParenField);
		}
		width = fontMetrics.charsWidth(new char[]{')'}, 0, 1);
		TimeListingTextField closeParenField = new TimeListingTextField(fn.tick, fn.pc, ")", x, width, fontMetrics, this.hlFactory);
		x += width;
		fields.add(closeParenField);
		if(fn.retdep != null && fn.retval != null) {
			width = fontMetrics.charsWidth(new char[]{' ','=',' '}, 0, 3);
			TimeListingTextField eqField = new TimeListingTextField(fn.tick, fn.pc, " = ", x, width, fontMetrics, this.hlFactory);
			x += width;
			fields.add(eqField);
			String display = String.format("0x%x", fn.retval);
			width = fontMetrics.charsWidth(display.toCharArray(), 0, display.length());
			fields.add(new TimeListingOperationField(fn.retdep, null, fn.retval, fn.tick, fn.pc, false, display, "return value " + display, x, width, fontMetrics, this.hlFactory));
			x += width;
		}
		w = x - start;
		fn.width = w;
		return fields;
	}
	
	public Layout getLayoutForInstruction(DataflowInstructionWithEffects ins) {
		Address addr = MadnessPlugin.flatApi.toAddr(Long.toHexString(ins.pc));
		String fnOffsetStr = functionRelativeAddressString(addr);
		if(fnOffsetStr == null) fnOffsetStr = "<UNKNOWN>";
		
		int x = 2*TimeListingSettings.PAD_WIDTH;
		int width = TimeListingSettings.TICK_FIELD_WIDTH;
		TimeListingTickField tickField = new TimeListingTickField(ins.tick, x, width, fontMetrics, this.hlFactory);
		x += width;
		width = TimeListingSettings.PC_FIELD_WIDTH;
		TimeListingPCField pcField = new TimeListingPCField(ins.tick, ins.pc, x, width, fontMetrics, this.hlFactory);
		x += width;
		width = TimeListingSettings.FN_OFFSET_FIELD_WIDTH;
		TimeListingTextField fnOffsetField = new TimeListingTextField(ins.tick, ins.pc, fnOffsetStr, x, width, fontMetrics, this.hlFactory);
		x += width;
		
		width = TimeListingSettings.DISAS_FIELD_WIDTH;
		TimeListingTextField disasField = new TimeListingTextField(ins.tick, ins.pc, ins.disas, x, width, fontMetrics, this.hlFactory);
		x += width;

		ArrayList<Field> fields = new ArrayList<>();
		fields.add(tickField);
		fields.add(pcField);
		fields.add(fnOffsetField);
		fields.add(disasField);
		if(ins.function != null) {
			fields.addAll(getLayoutForFunction(ins.function, x));
			x += ins.function.width + TimeListingSettings.PAD_WIDTH;
		}
		for(int i = 0; i < ins.effects.size(); i++) {
			DataflowEffect eff = ins.effects.get(i);
			String display;
			String desc;
			String valstr;
			String addrname;
			switch(eff.type) {
			case REG_WRITE:
				display = String.format("%s = 0x%x", eff.destStr, eff.val);
				desc = String.format("register value 0x%x written", eff.val);
				width = fontMetrics.charsWidth(display.toCharArray(), 0, display.length());
				fields.add(new TimeListingOperationField(eff.index, null, eff.val, ins.tick, ins.pc, false, display, desc, x, width, fontMetrics, this.hlFactory));
				break;
			case MEM_READ:
				valstr = eff.val== null ? "?" : String.format("0x%x", eff.val);
				addrname = plugin.getObjectCache().getName(eff.addr, ins.tick, (int)eff.size);
				if(addrname == null) addrname = "";
				else addrname += " @ ";
				display = String.format("Read [%s0x%x]:%d = %s", addrname, eff.addr, eff.size, valstr);
				desc = String.format("memory value %s read", valstr);
				width = fontMetrics.charsWidth(display.toCharArray(), 0, display.length());
				fields.add(new TimeListingOperationField(eff.index, null, eff.val, ins.tick, ins.pc, false, display, desc, x, width, fontMetrics, this.hlFactory));
				break;
			case MEM_WRITE:
				valstr = eff.val== null ? "?" : String.format("0x%x", eff.val);
				addrname = plugin.getObjectCache().getName(eff.addr, ins.tick, (int)eff.size);
				if(addrname == null) addrname = "";
				else addrname += " @ ";
				display = String.format("Write [%s0x%x]:%d = %s", addrname, eff.addr, eff.size, valstr);
				desc = String.format("memory value %s written", valstr);
				width = fontMetrics.charsWidth(display.toCharArray(), 0, display.length());
				fields.add(new TimeListingOperationField(eff.index, eff.addr, eff.val, ins.tick, ins.pc, true, display, desc, x, width, fontMetrics, this.hlFactory));
				break;
			case MEM_ACCESS:
				if(eff.val == null) addrname = null;
				else addrname = plugin.getObjectCache().getName(eff.val.longValue(), ins.tick, (int)eff.size);
				if(addrname == null) addrname = "";
				else addrname += " @ ";
				display = String.format("Access %s0x%x", addrname, eff.val);
				desc = String.format("address %s0x%x accessed", addrname, eff.val);
				width = fontMetrics.charsWidth(display.toCharArray(), 0, display.length());
				fields.add(new TimeListingOperationField(eff.index, eff.val.longValue(), eff.val, ins.tick, ins.pc, false, display, desc, x, width, fontMetrics, this.hlFactory));
				break;
			case BRANCH:
				display = "BRANCH";
				desc = String.format("branch target 0x%x", eff.val);
				width = fontMetrics.charsWidth(display.toCharArray(), 0, display.length());
				fields.add(new SimpleTextField(display, fontMetrics, x, width, true, this.hlFactory));
				break;
			}
			x += width;
			x += TimeListingSettings.PAD_WIDTH;
		}
		Field[] fs = fields.toArray(new Field[0]);
		RowLayout r = new RowLayout(fs, 0);
		return r;
	}

	@Override
	public void addLayoutModelListener(LayoutModelListener listener) {
		this.modelListeners.add(listener);
		
	}

	@Override
	public void removeLayoutModelListener(LayoutModelListener listener) {
		this.modelListeners.remove(listener);
	}

	@Override
	public void flushChanges() {

	}


	private class TestHighlightFactory implements FieldHighlightFactory {
		
		private Long hlOrigin = null;
		private HashMap<Long, Long> hlIndices;
		
		public void resetHighlight() {
			hlOrigin = null;
			this.hlIndices = new HashMap<>();
		}
		
		public void setOrigin(Long idx) {
			this.hlOrigin = idx;
		}
		
		public void addHighlight(Long idx, Long dist) {
			this.hlIndices.put(idx, dist); 
		}
		
		@Override
		public Highlight[] createHighlights(Field field, String text, int cursorTextOffset) {
			// TODO Auto-generated method stub
			//return new Highlight[] {new Highlight(0, 5, java.awt.Color.BLUE)};
			if(field instanceof SpacetimeOperationField) {
				SpacetimeOperationField sf = (SpacetimeOperationField) field;
				if(this.hlOrigin != null && this.hlOrigin.equals(sf.getIndex())) {
					return new Highlight[] {new Highlight(0, text.length(), new java.awt.Color(0xaa, 0xff, 0xaa))};
				} else if(this.hlIndices != null && this.hlIndices.containsKey(sf.getIndex())) {
					return new Highlight[] {new Highlight(0, text.length(), new java.awt.Color(0xdd, 0xff, 0))};
				}
				return new Highlight[] {new Highlight(0, text.length(), new java.awt.Color(0xdd, 0xee, 0xff))};
			}
			return new Highlight[] {};
		}
	
	}


	@Override
	public void queryCompleted(List<JSONObject> results, String tag) {
		if(tag.equals("instrace")) {
			for(int i = 0; i < results.size(); i++) {
				try {
					JSONObject obj = results.get(i);
					Long ty = obj.getLong("type");
					if(ty == 0) {
						DataflowInstructionWithEffects ins = new DataflowInstructionWithEffects(obj, plugin);
						this.instructions.add(ins);
						if(ins.function != null) {
							this.functions.add(ins.function);
						}
					}
				} catch(Exception e) {
					e.printStackTrace();
					continue;
				}
			}
			this.reloadModel();
			provider.refresh();
		}
	}
}

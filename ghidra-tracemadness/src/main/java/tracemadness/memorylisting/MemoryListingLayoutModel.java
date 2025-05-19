package tracemadness.memorylisting;

import java.awt.Dimension;
import java.awt.FontMetrics;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;

import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;
import tracemadness.dataflowinfo.DataflowSpace;
import tracemadness.dataflowinfo.DataflowSpaceMemoryByte;
import tracemadness.dataflowinfo.DataflowSpaceOperation;
import tracemadness.dataflowinfo.DataflowSpaceWithValueRange;
import tracemadness.listingfield.SpacetimeOperationField;
import tracemadness.memindex.MemoryValueQueryResult;
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
public class MemoryListingLayoutModel implements LayoutModel, MadnessQueryResultListener {

	public MadnessPlugin plugin;
	private MemoryListingProvider provider;
	private FontMetrics fontMetrics;
	private FieldHighlightFactory hlFactory; 
	private MemoryListingView view;
	private List<DataflowSpaceMemoryByte> space;
	private Map<BigInteger, Layout> layoutCache = new HashMap<>();;
	private Map<BigInteger, Long> indexToAddress = new HashMap<>();;
	private Map<Long, BigInteger> addressToIndex = new HashMap<>();;
	
	public MemoryListingLayoutModel(MadnessPlugin plugin, MemoryListingProvider provider, MemoryListingView view, FontMetrics fontMetrics) {
		this.plugin = plugin;
		this.provider = provider;
		this.view = view;
		// TODO get the font from Ghidra
		this.fontMetrics = fontMetrics;
		this.hlFactory = new SpaceListingHighlightFactory();
		this.loadSpace();
	}
	
	public Long getAddress(BigInteger index) {
		if(this.indexToAddress.containsKey(index)) {
			return this.indexToAddress.get(index);
		}
		return null;
	}

	public BigInteger getAddressIndex(Long addr) {
		if(this.addressToIndex.containsKey(addr)) {
			return this.addressToIndex.get(addr);
		}
		return null;
	}

	private void loadSpace()  {
		this.space = new ArrayList<>();

		try {
			ArrayList<MemoryValueQueryResult> res = plugin.memory.getMemory(this.view.getViewParam(MemoryListingView.VIEW_PARAM.TICK.name()), this.view.getViewParam(MemoryListingView.VIEW_PARAM.ADDR_START.name()), this.view.getViewParam(MemoryListingView.VIEW_PARAM.LEN.name()), null, 10);
			for(var r : res) {
				this.space.addAll(r.bytes);				
			}
			this.reloadModel();
		} catch(Exception e) {
			e.printStackTrace();
			return;
		}
	}
	
	public void reloadModel() {
		this.layoutCache = new HashMap<>();
		this.indexToAddress = new HashMap<>();
		this.addressToIndex = new HashMap<>();
		List<DataflowSpaceMemoryByte> events = new ArrayList<DataflowSpaceMemoryByte>();
		events.addAll(this.space);
		Collections.sort(events);
		BigInteger index = BigInteger.ZERO;
		for(int i = 0; i < events.size(); i++) {
			DataflowSpaceMemoryByte s = events.get(i);
			this.layoutCache.put(index, getLayoutForSpace(s));
			this.indexToAddress.put(index, s.addr);
			this.addressToIndex.put(s.addr, index);
			index = index.add(BigInteger.ONE);
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
		return new Dimension(MemoryListingSettings.MAX_WIDTH, 500);
	}

	@Override
	public BigInteger getNumIndexes() {
		// TODO Auto-generated method stub
		return BigInteger.valueOf(this.space.size());
	}

	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		if(index.longValue() >= this.space.size()) return null;
		if(index.longValue() <= -1) return null;
		return index.add(new BigInteger("1"));
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		if(index.longValue() >= this.space.size()+1) return null;
		if(index.longValue() <= 0) return null;
		return index.add(new BigInteger("-1"));
	}

	@Override
	public Layout getLayout(BigInteger index) {
		if(this.layoutCache.containsKey(index)) {
			return this.layoutCache.get(index);
		}
		return null;
	}

	public Layout getLayoutForSpace(DataflowSpaceMemoryByte s) {
		int x = MemoryListingSettings.PAD_WIDTH;
		int width = MemoryListingSettings.ADDR_FIELD_WIDTH;
		String addrname = "";
		HashSet<String> names = new HashSet<>();
		String n = plugin.objectCache.getName(s.addr, s.tick, 1);
		if(n != null) {
			addrname += " " + n;
		}
		
		MemoryListingAddrField addrField = new MemoryListingAddrField(s.addr, s.tick, String.format("0x%x%s", s.addr, addrname), x, width, fontMetrics, this.hlFactory);
		x += width;
		String desc = "";
		String valstr = 0x30 <= s.value && s.value <= 0x7a ? String.format("0x%x '%s'", s.value, Character.toString((char)s.value)) : String.format("0x%x", s.value);
		desc = String.format("%s", valstr);
		MemoryListingAddrField valField = new MemoryListingAddrField(s.addr, s.tick, desc, x, width, fontMetrics, this.hlFactory);
		x += width;
		
		ArrayList<Field> fields = new ArrayList<>();
		fields.add(addrField);
		fields.add(valField);
		Field[] fs = fields.toArray(new Field[0]);
		RowLayout r = new RowLayout(fs, 0);
		return r;
	}

	@Override
	public void addLayoutModelListener(LayoutModelListener listener) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeLayoutModelListener(LayoutModelListener listener) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void flushChanges() {
		// TODO Auto-generated method stub
		
	}


	private class SpaceListingHighlightFactory implements FieldHighlightFactory {
		
		@Override
		public Highlight[] createHighlights(Field field, String text, int cursorTextOffset) {
			// TODO Auto-generated method stub
			//return new Highlight[] {new Highlight(0, 5, java.awt.Color.BLUE)};
			if(field instanceof SpacetimeOperationField) {
				SpacetimeOperationField sf = (SpacetimeOperationField) field;
				if(sf.isWrite()) {
					return new Highlight[] {new Highlight(0, text.length(), new java.awt.Color(0xff, 0xdd, 0xdd))};
				}
				return new Highlight[] {new Highlight(0, text.length(), new java.awt.Color(0xdd, 0xdd, 0xff))};
			}
			return new Highlight[] {};
		}
	
	}


	@Override
	public void queryCompleted(List<JSONObject> results, String tag) {
		for(int i = 0; i < results.size(); i++) {
			try {
				JSONObject obj = results.get(i);
				MemoryValueQueryResult s = new MemoryValueQueryResult(obj);
				for(var b : s.bytes) {
					this.space.add(b);
				}
			} catch(Exception e) {
				e.printStackTrace();
				continue;
			}
		}
		this.reloadModel();
		this.provider.refresh();
	}
}

package tracemadness.spacelisting;

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
import tracemadness.dataflowinfo.DataflowSpaceOperation;
import tracemadness.dataflowinfo.DataflowSpaceWithValueRange;
import tracemadness.listingfield.SpacetimeOperationField;
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
public class SpaceListingLayoutModel implements LayoutModel, MadnessQueryResultListener {

	public MadnessPlugin plugin;
	private SpaceListingProvider provider;
	private FontMetrics fontMetrics;
	private FieldHighlightFactory hlFactory; 
	private SpaceListingView view;
	private List<DataflowSpaceWithValueRange> space;
	private Map<BigInteger, Layout> layoutCache;
	private Map<BigInteger, Long> indexToAddress;
	private Map<Long, BigInteger> addressToIndex;
	
	public SpaceListingLayoutModel(MadnessPlugin plugin, SpaceListingProvider provider, SpaceListingView view, FontMetrics fontMetrics) {
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
		String[] params = { view.toAQLString() }; // TODO filters
		this.space = new ArrayList<>();

		try {
			plugin.runQuery("fullspace", params, this, "space");
		} catch(Exception e) {
			e.printStackTrace();
			return;
		}
	}
	
	public void reloadModel() {
		this.layoutCache = new HashMap<>();
		this.indexToAddress = new HashMap<>();
		this.addressToIndex = new HashMap<>();
		List<DataflowSpace> events = new ArrayList<DataflowSpace>();
		events.addAll(this.space);
		Collections.sort(events);
		BigInteger index = BigInteger.ZERO;
		for(int i = 0; i < events.size(); i++) {
			DataflowSpace dt = events.get(i);
			DataflowSpaceWithValueRange s = (DataflowSpaceWithValueRange) dt;
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
		return new Dimension(SpaceListingSettings.MAX_WIDTH, 500);
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

	public Layout getLayoutForSpace(DataflowSpaceWithValueRange s) {	
		String valstr;
		int x = SpaceListingSettings.PAD_WIDTH;
		int width = SpaceListingSettings.ADDR_FIELD_WIDTH;
		String addrname = "";
		HashSet<String> names = new HashSet<>();
		for(DataflowSpaceOperation op : s.operations) {
			String n = plugin.objectCache.getName(s.addr, (int)op.tick.longValue(), (int)op.size.longValue());
			if(n != null) {
				names.add(n);
			}
		}
		for(String n : names) {
			addrname += " " + n;
		}
		addrname += String.format(":%d", s.size);
		SpaceListingAddrField addrField = new SpaceListingAddrField(s.addr, String.format("0x%x%s", s.addr, addrname), x, width, fontMetrics, this.hlFactory);
		x += width;
		width = SpaceListingSettings.ACCESSES_FIELD_WIDTH;
		SpaceListingAccessesField readsField = new SpaceListingAccessesField(s.addr, false, String.format("%d read%s", s.reads, (s.reads == 1 ? "" : "s")), x, width, fontMetrics, this.hlFactory);
		x += width;
		width = SpaceListingSettings.ACCESSES_FIELD_WIDTH;
		SpaceListingAccessesField writesField = new SpaceListingAccessesField(s.addr, true /* is_write */, String.format("%d writes", s.writes), x, width, fontMetrics, this.hlFactory);
		x += width;
		width = SpaceListingSettings.MINMAX_FIELD_WIDTH;
		String desc = "";
		String minvalstr = 0x30 <= s.minval && s.minval <= 0x7a ? String.format("0x%x '%s'", s.minval, Character.toString((char)s.minval.longValue())) : String.format("0x%x", s.minval);
		String maxvalstr = 0x30 <= s.maxval && s.maxval <= 0x7a ? String.format("0x%x '%s'", s.maxval, Character.toString((char)s.maxval.longValue())) : String.format("0x%x", s.maxval);   
		if(s.minval.equals(s.maxval)) {
			desc = String.format("%s", minvalstr);
		} else {
			desc = String.format("%s - %s", minvalstr, maxvalstr);
		}
		SpaceListingAddrField minMaxField = new SpaceListingAddrField(s.addr, desc, x, width, fontMetrics, this.hlFactory);
		x += width;
		
		ArrayList<Field> fields = new ArrayList<>();
		fields.add(addrField);
		fields.add(readsField);
		fields.add(writesField);
		fields.add(minMaxField);
		int i = 0;
		for(DataflowSpaceOperation op : s.operations) {
			if(i < 11) {
				valstr = String.format("0x%x", op.val); 
				width = fontMetrics.charsWidth(valstr.toCharArray(), 0, valstr.length());
				width += SpaceListingSettings.PAD_WIDTH;
				SpaceListingOperationField sf = new SpaceListingOperationField(s.addr, op.index, op.tick, op.val, op.is_write, valstr, "Data value " + valstr, x, width, fontMetrics, this.hlFactory);
				fields.add(sf);
				x += width;
			} else {
				width = SpaceListingSettings.MINMAX_FIELD_WIDTH;
				SpaceListingAddrField dotsField = new SpaceListingAddrField(s.addr, "...", x, width, fontMetrics, this.hlFactory);
				fields.add(dotsField);
				x += width;
				break;
			}
		}
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
				DataflowSpaceWithValueRange s = new DataflowSpaceWithValueRange(obj);
				this.space.add(s);
			} catch(Exception e) {
				e.printStackTrace();
				continue;
			}
		}
		this.reloadModel();
		this.provider.refresh();
	}
}

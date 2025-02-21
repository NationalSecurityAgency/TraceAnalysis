package tracemadness.slicelisting;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;

@SuppressWarnings("serial")
public class SliceListingTableModel extends ThreadedTableModel<SliceItem, MadnessPlugin> implements MadnessQueryResultListener {

	public Address referenceAddress = null;
	public MadnessPlugin plugin;
	public long index;
	public long depth;
	public boolean forwards;
	private ArrayList<SliceItem> slice;

	public SliceListingTableModel(MadnessPlugin plugin, long index, long depth, boolean forwards) {
		super("timeline", plugin.getTool());
		this.plugin = plugin;
		this.index = index;
		this.depth = depth;
		this.forwards = forwards;
		this.slice = new ArrayList<>();
		String[] params = new String[] {Long.toString(this.index), Long.toString(this.depth), this.forwards ? "inbound" : "outbound"};
		this.plugin.runQuery("getslice", params, this, "slice");
	}

	protected TableColumnDescriptor<SliceItem> createTableColumnDescriptor() {
		TableColumnDescriptor<SliceItem> descriptor = new TableColumnDescriptor<SliceItem>();
		descriptor.addVisibleColumn(new TickTableColumn());
		descriptor.addVisibleColumn(new ModuleTableColumn());
		descriptor.addVisibleColumn(new PCTableColumn());
		descriptor.addVisibleColumn(new FunctionTableColumn());
		descriptor.addVisibleColumn(new DisasTableColumn());
		descriptor.addVisibleColumn(new ValueTableColumn());
		descriptor.addVisibleColumn(new NameTableColumn());
		return descriptor;
	}

	private class ModuleTableColumn extends AbstractDynamicTableColumn<SliceItem, String, Object> {

		@Override
		public String getColumnName() {
			return "Module";
		}

		@Override
		public String getValue(SliceItem rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			Address a = MadnessPlugin.flatApi.toAddr(rowObject.pc);
			return plugin.getProgramLocation(a, false).getProgram().getName();
		}
	}
	private class PCTableColumn extends AbstractDynamicTableColumn<SliceItem, Address, Object> {

		@Override
		public String getColumnName() {
			return "PC";
		}

		@Override
		public Address getValue(SliceItem rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			Address a = MadnessPlugin.flatApi.toAddr(rowObject.pc);
			return plugin.getProgramLocation(a, false).getAddress();
		}
	}
	private class FunctionTableColumn extends AbstractDynamicTableColumn<SliceItem, String, Object> {

		@Override
		public String getColumnName() {
			return "Function";
		}

		@Override
		public String getValue(SliceItem rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return plugin.getFunctionContaining(MadnessPlugin.flatApi.toAddr(rowObject.pc)).getName();
		}
	}
	private class DisasTableColumn extends AbstractDynamicTableColumn<SliceItem, String, Object> {

		@Override
		public String getColumnName() {
			return "Instruction";
		}

		@Override
		public String getValue(SliceItem rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.disas;
		}
	}
	private class ValueTableColumn extends AbstractDynamicTableColumn<SliceItem, BigInteger, Object> {

		@Override
		public String getColumnName() {
			return "Value";
		}

		@Override
		public BigInteger getValue(SliceItem rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.value;
		}
	}
	private class NameTableColumn extends AbstractDynamicTableColumn<SliceItem, String, Object> {

		@Override
		public String getColumnName() {
			return "Destination";
		}

		@Override
		public String getValue(SliceItem rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.reg.length() > 0 ? rowObject.reg : String.format("0x%x",rowObject.addr);
		}
	}
	private class TickTableColumn extends AbstractDynamicTableColumn<SliceItem, Long, Object> {

		@Override
		public String getColumnName() {
			return "Tick";
		}

		@Override
		public Long getValue(SliceItem rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.tick;
		}
	}

	protected void doLoad(Accumulator<SliceItem> accumulator, TaskMonitor monitor) throws CancelledException {
		try {
			for(SliceItem i : this.slice) {
				accumulator.add(i);
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public MadnessPlugin getDataSource() {
		return this.plugin;
	}

	@Override
	public void queryCompleted(List<JSONObject> results, String tag) {
		this.slice = new ArrayList<>();
		for(int i = 0; i < results.size(); i++) {
			JSONObject obj = results.get(i);
			this.slice.add(new SliceItem(obj));
		}
		this.reload();
	}
}
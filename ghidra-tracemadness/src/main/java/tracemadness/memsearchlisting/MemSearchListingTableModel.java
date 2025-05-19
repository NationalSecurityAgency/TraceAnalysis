package tracemadness.memsearchlisting;

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
import tracemadness.memindex.MemorySearchResult;

@SuppressWarnings("serial")
public class MemSearchListingTableModel extends ThreadedTableModel<MemSearchItem, MadnessPlugin> implements MadnessQueryResultListener {

	public Address referenceAddress = null;
	public MadnessPlugin plugin;
	public long index;
	public long depth;
	public boolean forwards;
	private ArrayList<MemSearchItem> items;

	public MemSearchListingTableModel(MadnessPlugin plugin, byte[] str) {
		super("timeline", plugin.getTool());
		this.plugin = plugin;
		ArrayList<MemorySearchResult> res = this.plugin.memory.searchMemory(str, null, 10);
		this.items = new ArrayList<>();
		if(res == null) return;
		for(var r : res) {
			for(int i = 0; i < r.addresses.size(); i++) {
				MemSearchItem item = new MemSearchItem(r.addresses.get(i).longValue(), r.createticks.get(i), r.destroyticks.get(i));
				this.items.add(item);
			}
		}
		this.reload();
	}

	protected TableColumnDescriptor<MemSearchItem> createTableColumnDescriptor() {
		TableColumnDescriptor<MemSearchItem> descriptor = new TableColumnDescriptor<MemSearchItem>();
		descriptor.addVisibleColumn(new AddrTableColumn());
		descriptor.addVisibleColumn(new CreateTickTableColumn());
		descriptor.addVisibleColumn(new DestroyTickTableColumn());
		return descriptor;
	}
	private class AddrTableColumn extends AbstractDynamicTableColumn<MemSearchItem, Address, Object> {

		@Override
		public String getColumnName() {
			return "Buffer address";
		}

		@Override
		public Address getValue(MemSearchItem rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			Address a = MadnessPlugin.flatApi.toAddr(rowObject.address);
			return a;
		}
	}
	private class CreateTickTableColumn extends AbstractDynamicTableColumn<MemSearchItem, Long, Object> {

		@Override
		public String getColumnName() {
			return "Creation Tick";
		}

		@Override
		public Long getValue(MemSearchItem rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.create_tick;
		}
	}
	private class DestroyTickTableColumn extends AbstractDynamicTableColumn<MemSearchItem, Long, Object> {

		@Override
		public String getColumnName() {
			return "Destruction Tick";
		}

		@Override
		public Long getValue(MemSearchItem rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.destroy_tick;
		}
	}

	protected void doLoad(Accumulator<MemSearchItem> accumulator, TaskMonitor monitor) throws CancelledException {
		try {
			for(MemSearchItem i : this.items) {
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
		this.items = new ArrayList<>();
		// TODO make search query async
		this.reload();
	}
}
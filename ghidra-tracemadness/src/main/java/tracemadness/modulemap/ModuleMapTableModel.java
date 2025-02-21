package tracemadness.modulemap;

import java.lang.Long;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;
import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;

@SuppressWarnings("serial")
public class ModuleMapTableModel extends AddressBasedTableModel<ModuleInfo> implements MadnessQueryResultListener {

	public Address referenceAddress = null;
	public Program currentProgram;
	public MadnessPlugin plugin;
	private ModuleMap map;
	private ArrayList<ModuleInfo> modules;
	
	public ModuleMapTableModel(MadnessPlugin plugin, Program program, ModuleMap m) {
		super(program.getName(), plugin.getTool(), program, null, false);
		this.currentProgram = program;
		this.plugin = plugin;
		this.map = m;
		this.modules = new ArrayList<>();
		this.plugin.runQuery("modules",  new String[] {}, this,  "modules");
	}

	@Override
	public Address getAddress(int row) {
		return MadnessPlugin.flatApi.toAddr(getRowObject(row).getBase());
	}

	public void setReferenceAddress(Address a) {
		this.referenceAddress = a;
	}

	@Override
	protected TableColumnDescriptor<ModuleInfo> createTableColumnDescriptor() {
		TableColumnDescriptor<ModuleInfo> descriptor = new TableColumnDescriptor<ModuleInfo>();
		descriptor.addVisibleColumn(new NameTableColumn());
		descriptor.addVisibleColumn(new AddressTableColumn());
		descriptor.addVisibleColumn(new SizeTableColumn());
		return descriptor;
	}

	private class AddressTableColumn extends AbstractDynamicTableColumn<ModuleInfo, Address, Object> {

		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public Address getValue(ModuleInfo rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return MadnessPlugin.flatApi.toAddr(rowObject.getBase().longValue());
		}
	}

	private class NameTableColumn extends AbstractDynamicTableColumn<ModuleInfo, String, Object> {

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(ModuleInfo rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getName();
		}
	}

	private class SizeTableColumn extends AbstractDynamicTableColumn<ModuleInfo, Long, Object> {

		@Override
		public String getColumnName() {
			return "Size";
		}

		@Override
		public Long getValue(ModuleInfo rowObject, Settings settings, Object data, ServiceProvider services)
				throws IllegalArgumentException {
			return (long)(rowObject.getSize());
		}
	}

	@Override
	protected void doLoad(Accumulator<ModuleInfo> accumulator, TaskMonitor monitor)
			throws CancelledException {
		for(ModuleInfo i : this.modules) {
			accumulator.add(i);
		}
	}

	@Override
	public void queryCompleted(List<JSONObject> results, String tag) {
		this.modules = new ArrayList<>();

		int length = results.size();
		long prevBase = Long.MAX_VALUE;
		for(int i = 0; i < length; i++) {
			JSONObject modJson = results.get(length-1 - i);
			String name = modJson.getString("name");
			String path = modJson.getString("path");
			long base = modJson.getBigInteger("base").longValue();
			long size = 0;
			if (modJson.has("size")) {
				size = modJson.getLong("size");
			} else {
				size = prevBase - base;					
			}
			ModuleInfo m = new ModuleInfo(name, path, base, size);
			this.modules.add(m);
			prevBase = base;
		}

		this.reload();
	}
}

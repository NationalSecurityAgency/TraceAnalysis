package tracemadness.objectmanager;

import java.util.List;
import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;
import tracemadness.MadnessPlugin;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.objectdata.ObjectPhase;
import tracemadness.View;

@SuppressWarnings("serial")
public class ObjectManagerTableModel extends ThreadedTableModel<ObjectInfo, MadnessPlugin> {

	public Address referenceAddress = null;
	public Program currentProgram;
	public MadnessPlugin plugin;

	public View view;

	public ObjectManagerTableModel(MadnessPlugin plugin, Program program) {
		super(program.getName(), plugin.getTool(), null);
		this.currentProgram = program;
		this.plugin = plugin;
		this.view = new ObjectManagerView();
	}

	public void setReferenceAddress(Address a) {
		this.referenceAddress = a;
	}

	@Override
	protected TableColumnDescriptor<ObjectInfo> createTableColumnDescriptor() {
		TableColumnDescriptor<ObjectInfo> descriptor = new TableColumnDescriptor<ObjectInfo>();
		descriptor.addVisibleColumn(new AddressTableColumn());
		descriptor.addVisibleColumn(new SizeTableColumn());
		descriptor.addVisibleColumn(new TypeTableColumn());
		descriptor.addVisibleColumn(new NameTableColumn());
		descriptor.addVisibleColumn(new StartTableColumn());
		descriptor.addVisibleColumn(new EndTableColumn());
		return descriptor;
	}

	private class AddressTableColumn extends AbstractDynamicTableColumn<ObjectInfo, Address, Object> {

		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public Address getValue(ObjectInfo rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return MadnessPlugin.flatApi.toAddr(rowObject.getBase());
		}
	}

	private class TypeTableColumn extends AbstractDynamicTableColumn<ObjectInfo, String, Object> {

		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public String getValue(ObjectInfo rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			ObjectPhase[] timeline = rowObject.getTimeline();
			if(timeline.length > 0) {
				DataType ty = timeline[0].getType();
				if(ty != null) return ty.getName();
			}
			return String.format("unknown%d", rowObject.getSize());
		}
	}

	private class NameTableColumn extends AbstractDynamicTableColumn<ObjectInfo, String, Object> {

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(ObjectInfo rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getName();
		}
	}

	private class SizeTableColumn extends AbstractDynamicTableColumn<ObjectInfo, Long, Object> {

		@Override
		public String getColumnName() {
			return "Size";
		}

		@Override
		public Long getValue(ObjectInfo rowObject, Settings settings, Object data, ServiceProvider services)
				throws IllegalArgumentException {
			return (long)(rowObject.getSize());
		}
	}


	private class StartTableColumn extends AbstractDynamicTableColumn<ObjectInfo, Long, Object> {

		@Override
		public String getColumnName() {
			return "Birth";
		}

		@Override
		public Long getValue(ObjectInfo rowObject, Settings settings, Object data, ServiceProvider services)
				throws IllegalArgumentException {
			Long start = rowObject.getBirth();
			if(start == null) return 0L;
			return start;
		}
	}
	private class EndTableColumn extends AbstractDynamicTableColumn<ObjectInfo, Long, Object> {

		@Override
		public String getColumnName() {
			return "Death";
		}

		@Override
		public Long getValue(ObjectInfo rowObject, Settings settings, Object data, ServiceProvider services)
				throws IllegalArgumentException {
			Long end = rowObject.getDeath();
			if(end == null) return 0L;
			return end;
		}
	}

	@Override
	protected void doLoad(Accumulator<ObjectInfo> accumulator, TaskMonitor monitor)
			throws CancelledException {
		try {
			List<ObjectInfo> arr = this.plugin.objectCache.getObjects();
			for(ObjectInfo o : arr) {
				accumulator.add(o);
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public MadnessPlugin getDataSource() {
		// TODO Auto-generated method stub
		return null;
	}
}
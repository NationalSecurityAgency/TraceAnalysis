package tracemadness.objectmanager;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;
import tracemadness.MadnessPlugin;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.objectdata.ObjectPhase;
import tracemadness.View;

@SuppressWarnings("serial")
public class ObjectTimelineTableModel extends AddressBasedTableModel<ObjectPhase> {

	public Address referenceAddress = null;
	public MadnessPlugin plugin;
	public String currentObjectKey;
	public View view;

	public ObjectTimelineTableModel(MadnessPlugin plugin) {
		super("timeline", plugin.getTool(), MadnessPlugin.programManager.getCurrentProgram(), null, false);
		this.plugin = plugin;
		this.currentObjectKey = null;
	}

	@Override
	protected TableColumnDescriptor<ObjectPhase> createTableColumnDescriptor() {
		TableColumnDescriptor<ObjectPhase> descriptor = new TableColumnDescriptor<ObjectPhase>();
		descriptor.addVisibleColumn(new StartTableColumn());
		descriptor.addVisibleColumn(new TypeTableColumn());
		return descriptor;
	}

	private class TypeTableColumn extends AbstractDynamicTableColumn<ObjectPhase, String, Object> {

		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public String getValue(ObjectPhase rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			DataType ty = rowObject.getType();
			if(ty != null) return ty.getName();
			return "<unknown>";
		}
	}

	private class StartTableColumn extends AbstractDynamicTableColumn<ObjectPhase, Long, Object> {

		@Override
		public String getColumnName() {
			return "Start";
		}

		@Override
		public Long getValue(ObjectPhase rowObject, Settings settings, Object data, ServiceProvider services)
				throws IllegalArgumentException {
			Long start = rowObject.getStart();
			if(start == null) return 0L;
			return start;
		}
	}

	@Override
	protected void doLoad(Accumulator<ObjectPhase> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if(this.currentObjectKey == null) {
			return;
		}
		try {
			ObjectInfo obj = this.plugin.objectCache.getObjectByKey(this.currentObjectKey);
			if(obj == null) {
				return;
			}
			for(ObjectPhase o : obj.getTimeline()) {
				accumulator.add(o);
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public Address getAddress(int row) {
		// TODO Auto-generated method stub
		ObjectInfo obj = this.plugin.objectCache.getObjectByKey(this.currentObjectKey);
		if(obj == null) {
			return null;
		}
		return MadnessPlugin.flatApi.toAddr(obj.getBase());
	}
}
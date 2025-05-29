package tracemadness.witnessmanager;

import java.util.List;
import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import tracemadness.MadnessPlugin;
import tracemadness.objectdata.ObjectWitness;
import tracemadness.View;

@SuppressWarnings("serial")
public class WitnessManagerTableModel extends ThreadedTableModel<ObjectWitness, MadnessPlugin> {

	public Address referenceAddress = null;
	public Program currentProgram;
	public MadnessPlugin plugin;

	public View view;

	public WitnessManagerTableModel(MadnessPlugin plugin, Program program) {
		super(program.getName(), plugin.getTool(), null);
		this.currentProgram = program;
		this.plugin = plugin;
		this.view = new WitnessManagerView();
	}

	public void setReferenceAddress(Address a) {
		this.referenceAddress = a;
	}

	@Override
	protected TableColumnDescriptor<ObjectWitness> createTableColumnDescriptor() {
		TableColumnDescriptor<ObjectWitness> descriptor = new TableColumnDescriptor<ObjectWitness>();
		descriptor.addVisibleColumn(new ModuleTableColumn());
		descriptor.addVisibleColumn(new ModuleOffsetTableColumn());
		descriptor.addVisibleColumn(new EventTypeTableColumn());
		descriptor.addVisibleColumn(new InsFeatureTableColumn());
		descriptor.addVisibleColumn(new ObjectOffsetTableColumn());
		return descriptor;
	}

	private class ModuleTableColumn extends AbstractDynamicTableColumn<ObjectWitness, String, Object> {

		@Override
		public String getColumnName() {
			return "Module name";
		}

		@Override
		public String getValue(ObjectWitness rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.moduleName;
		}
	}
	private class ModuleOffsetTableColumn extends AbstractDynamicTableColumn<ObjectWitness, String, Object> {

		@Override
		public String getColumnName() {
			return "Module offset";
		}

		@Override
		public String getValue(ObjectWitness rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return String.format("0x%x", rowObject.offset);
		}
	}

	private class EventTypeTableColumn extends AbstractDynamicTableColumn<ObjectWitness, String, Object> {

		@Override
		public String getColumnName() {
			return "Event";
		}

		@Override
		public String getValue(ObjectWitness rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getEvent();
		}
	}
	private class ObjectOffsetTableColumn extends AbstractDynamicTableColumn<ObjectWitness, String, Object> {

		@Override
		public String getColumnName() {
			return "Object offset";
		}

		@Override
		public String getValue(ObjectWitness rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return String.format("0x%x", rowObject.objOffset);
		}
	}



	private class InsFeatureTableColumn extends AbstractDynamicTableColumn<ObjectWitness, String, Object> {

		@Override
		public String getColumnName() {
			return "Address source";
		}

		@Override
		public String getValue(ObjectWitness rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getFeature();
		}
	}


	@Override
	protected void doLoad(Accumulator<ObjectWitness> accumulator, TaskMonitor monitor)
			throws CancelledException {
		try {
			List<ObjectWitness> arr = this.plugin.getObjectCache().getWitnesses();
			for(ObjectWitness o : arr) {
				accumulator.add(o);
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
}
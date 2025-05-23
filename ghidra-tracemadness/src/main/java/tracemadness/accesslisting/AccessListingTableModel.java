package tracemadness.accesslisting;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.View;

@SuppressWarnings("serial")
public class AccessListingTableModel extends ThreadedTableModel<AnnotatedAccessEvent, MadnessPlugin> implements MadnessQueryResultListener {

	public Address referenceAddress = null;
	public AccessListingProvider provider;
	public MadnessPlugin plugin;
	private ArrayList<AnnotatedAccessEvent> space;
	public View view;

	public AccessListingTableModel(MadnessPlugin plugin, AccessListingProvider provider, AccessListingView view) {
		super("Access listing", plugin.getTool(), null);
		this.provider = provider;
		this.plugin = plugin;
		this.view = view;
		this.loadSpace();
	}
	public void setView(AccessListingView view) {
		this.view = view;
		this.loadSpace();
	}
	public void loadSpace()  {
		String[] params = { view.toAQLString() }; // TODO filters
		this.space = new ArrayList<>();

		try {
			plugin.runQuery("accesses", params, this, "accesses");
		} catch(Exception e) {
			e.printStackTrace();
			return;
		}
	}

	public void setReferenceAddress(Address a) {
		this.referenceAddress = a;
	}

	@Override
	protected TableColumnDescriptor<AnnotatedAccessEvent> createTableColumnDescriptor() {
		TableColumnDescriptor<AnnotatedAccessEvent> descriptor = new TableColumnDescriptor<AnnotatedAccessEvent>();
		descriptor.addVisibleColumn(new AddressTableColumn());
		descriptor.addVisibleColumn(new TickTableColumn());
		descriptor.addVisibleColumn(new PCTableColumn());
		descriptor.addVisibleColumn(new ModuleTableColumn());
		descriptor.addVisibleColumn(new FunctionTableColumn());
		descriptor.addVisibleColumn(new RawTableColumn());
		descriptor.addVisibleColumn(new SizeTableColumn());
		descriptor.addVisibleColumn(new IsWriteTableColumn());
		descriptor.addVisibleColumn(new ObjectNameTableColumn());
		descriptor.addVisibleColumn(new ObjectFieldTableColumn());
		return descriptor;
	}

	private class AddressTableColumn extends AbstractDynamicTableColumn<AnnotatedAccessEvent, Address, Object> {
		@Override
		public String getColumnName() { return "Address"; }
		@Override
		public Address getValue(AnnotatedAccessEvent rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			if(MadnessPlugin.flatApi == null) return null;
			return MadnessPlugin.flatApi.toAddr(rowObject.event.getAddr());
		}
	}
	private class TickTableColumn extends AbstractDynamicTableColumn<AnnotatedAccessEvent, Long, Object> {
		@Override
		public String getColumnName() { return "Tick"; }
		@Override
		public Long getValue(AnnotatedAccessEvent rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.event.getTick();
		}
	}
	private class PCTableColumn extends AbstractDynamicTableColumn<AnnotatedAccessEvent, Address, Object> {
		@Override
		public String getColumnName() { return "PC"; }
		@Override
		public Address getValue(AnnotatedAccessEvent rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			if(MadnessPlugin.flatApi == null) return null;
			return MadnessPlugin.flatApi.toAddr(rowObject.event.getPC());
		}
	}
	private class FunctionTableColumn extends AbstractDynamicTableColumn<AnnotatedAccessEvent, String, Object> {
		@Override
		public String getColumnName() { return "Function"; }
		@Override
		public String getValue(AnnotatedAccessEvent rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.func == null ? "?" : rowObject.func.getName();
		}
	}
	private class ModuleTableColumn extends AbstractDynamicTableColumn<AnnotatedAccessEvent, String, Object> {
		@Override
		public String getColumnName() { return "Module"; }
		@Override
		public String getValue(AnnotatedAccessEvent rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return "?";//plugin.getProgramLocation(MadnessPlugin.flatApi.toAddr(rowObject.event.getPC()), false).getProgram().getName();
		}
	}
	private class RawTableColumn extends AbstractDynamicTableColumn<AnnotatedAccessEvent, String, Object> {
		@Override
		public String getColumnName() { return "Raw Value"; }
		@Override
		public String getValue(AnnotatedAccessEvent rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			String ans = "";
			byte[] val = rowObject.event.getVal();
			for(int i = 0; i < val.length; i++) ans += String.format("%02x", val[i]);
			return ans;
		}
	}
	private class SizeTableColumn extends AbstractDynamicTableColumn<AnnotatedAccessEvent, Integer, Object> {
		@Override
		public String getColumnName() { return "Size"; }
		@Override
		public Integer getValue(AnnotatedAccessEvent rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.event.getSize();
		}
	}
	private class ObjectNameTableColumn extends AbstractDynamicTableColumn<AnnotatedAccessEvent, String, Object> {
		@Override
		public String getColumnName() { return "Object"; }
		@Override
		public String getValue(AnnotatedAccessEvent rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.obj == null ? "<none>" : rowObject.obj.getName();
		}
	}
	private class ObjectFieldTableColumn extends AbstractDynamicTableColumn<AnnotatedAccessEvent, String, Object> {
		@Override
		public String getColumnName() { return "Field"; }
		@Override
		public String getValue(AnnotatedAccessEvent rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.obj == null ? "<none>" : plugin.getObjectCache().getName(rowObject.obj.getBase(), rowObject.event.getTick(), (int)(long)rowObject.obj.getSize());
		}
	}
	private class IsWriteTableColumn extends AbstractDynamicTableColumn<AnnotatedAccessEvent, Boolean, Object> {
		@Override
		public String getColumnName() { return "Is Write"; }
		@Override
		public Boolean getValue(AnnotatedAccessEvent rowObject, Settings settings, Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.event.isWrite();
		}
	}


	@Override
	protected void doLoad(Accumulator<AnnotatedAccessEvent> accumulator, TaskMonitor monitor)
			throws CancelledException {
		try {
			long total = 0;
			long objValid = 0;
			long fieldValid = 0;
			for(AnnotatedAccessEvent e : this.space) {
				total++;
				if(e.hasValidObject()) objValid++;
				if(e.hasValidField()) fieldValid++;
				
				if(this.provider.objDisplay == AccessListingProvider.DISPLAY_MODE.ALL || 
						(this.provider.objDisplay == AccessListingProvider.DISPLAY_MODE.VALID && e.hasValidObject()) || 
						(this.provider.objDisplay == AccessListingProvider.DISPLAY_MODE.INVALID && !e.hasValidObject())) {
					if(this.provider.fieldDisplay == AccessListingProvider.DISPLAY_MODE.ALL || 
							(this.provider.fieldDisplay == AccessListingProvider.DISPLAY_MODE.VALID && e.hasValidField()) || 
							(this.provider.fieldDisplay == AccessListingProvider.DISPLAY_MODE.INVALID && !e.hasValidField())) {
						accumulator.add(e);
					}
				}
				if(this.provider.guiReady) {
					this.provider.objStatusLabel.setText(String.format("%d/%d valid (%f%%)", objValid, total, 100.0*(double)objValid/(double)total));
					this.provider.fieldStatusLabel.setText(String.format("%d/%d valid (%f%%)", fieldValid, total, 100.0*(double)fieldValid/(double)total));
					this.provider.refresh();
				}
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
		if(tag.equals("accesses")) {
			for(int i = 0; i < results.size(); i++) {
				try {
					JSONObject obj = results.get(i);
					AccessEvent e = new AccessEvent(obj);
					ObjectInfo info = plugin.getObjectCache().getObjectContaining(e.getAddr(), e.getTick());
					Function f = null;
					if(MadnessPlugin.flatApi != null) {
						ProgramLocation loc = plugin.getProgramLocation(MadnessPlugin.flatApi.toAddr(e.getPC()), false);
						f = loc.getProgram().getFunctionManager().getFunctionContaining(loc.getAddress());
					}
					this.space.add(new AnnotatedAccessEvent(e, info, f));
				} catch(Exception e) {
					e.printStackTrace();
					// 	sometimes this happens, say, if we cannot deduce values, e.g. at the beginning of the trace; nothing to be done; it is fine. probably
					continue;
				}
			}
			this.reload();
			if(this.provider.guiReady) {
				this.provider.refresh();
			}
		}
	}
}
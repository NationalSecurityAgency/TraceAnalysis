package tracemadness.objectmanager;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.swing.JPanel;

import org.json.JSONObject;

import docking.ActionContext;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.label.GDLabel;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import ghidra.util.task.TaskMonitor;
import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.objectdata.ObjectPhase;

public class ObjectTimelineComponent implements ActionContextProvider {

	private MadnessPlugin plugin;
	private GhidraThreadedTablePanel<?> tablePanel;
	private GhidraTable objTable;
	public ObjectTimelineTableModel timelineModel;
	private ObjectInfo currentObject;
	ObjectManagerProvider provider;

	public ObjectTimelineComponent(MadnessPlugin plugin, ObjectManagerProvider provider, String description) {
		this.plugin = plugin;
		this.provider = provider;
		this.createContextActions();
		this.timelineModel = new ObjectTimelineTableModel(this.plugin);
	}
	
	public void setObject(ObjectInfo obj) {
		this.currentObject = obj;
		this.timelineModel.currentObjectKey = obj.getKey();
		this.timelineModel.reload();
	}

	@Override
	public ActionContext getActionContext(MouseEvent ev) {
		ObjectPhase sel = this.getSelectedObject();
		if(sel == null) return null;
		return new ObjectTimelineActionContext(this.provider, this.currentObject, sel);
	}
	
	private void createContextActions() {

		{
			AccessesContextAction a = new AccessesContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Object accesses during phase"}, null, "object"));
			this.plugin.getTool().addAction(a);
		}
		{
			SetStartContextAction a = new SetStartContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Set phase start to current tick"}, null, "edit"));
			this.plugin.getTool().addAction(a);
		}
		{
			NewPhaseStartAtTickContextAction a = new NewPhaseStartAtTickContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Create new phase with a given type at tick"}, null, "edit"));
			this.plugin.getTool().addAction(a);
		}
		{
			NewPhaseNewTypeStartAtTickContextAction a = new NewPhaseNewTypeStartAtTickContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Create new phase with a new type at tick"}, null, "edit"));
			this.plugin.getTool().addAction(a);
		}
		{
			RemovePhaseContextAction a = new RemovePhaseContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Remove phase"}, null, "edit"));
			this.plugin.getTool().addAction(a);
		}
		{
			EditTypeContextAction a = new EditTypeContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Choose phase type"}, null, "type"));
			this.plugin.getTool().addAction(a);
		}
		{
			AutostructPhaseContextAction a = new AutostructPhaseContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Auto-create new type for phase"}, null, "type"));
			this.plugin.getTool().addAction(a);
		}
		{
			AutoFillStructPhaseContextAction a = new AutoFillStructPhaseContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Auto-fill existing type for phase"}, null, "type"));
			this.plugin.getTool().addAction(a);
		}
		{
			AutoPropagatePhasePointerContextAction a = new AutoPropagatePhasePointerContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Use phase type for instances"}, null, "type"));
			this.plugin.getTool().addAction(a);
		}
	}

	public List<ObjectPhase> getSelectedObjects() {
		int[] rows = this.objTable.getSelectedRows();
		ArrayList<ObjectPhase> sel = new ArrayList<>();
		for(int i = 0; i < rows.length; i++) {
			sel.add(this.timelineModel.getRowObject(rows[i]));
		}
		return sel;
	}

	public ObjectPhase getSelectedObject() {		
		int row = this.objTable.getSelectedRow();
		if(row < 0) {
			return null;
		}
		return this.timelineModel.getRowObject(row);
	}
	
	private JPanel buildPanel() {
		JPanel panel = new JPanel(new GridLayout());

		panel.setLayout(new BorderLayout());
		Component objMgrTablePanel = buildTablePanel();

		panel.add(objMgrTablePanel, BorderLayout.CENTER);

		return panel;
	}

	public ObjectManagerView createView(String ty, Map<String, Long> params) {
		return new ObjectManagerView(ty, params);
	}

	private Component buildTablePanel() {
		timelineModel = new ObjectTimelineTableModel(this.plugin);
		tablePanel = new GhidraThreadedTablePanel<>(timelineModel, 1000);
		objTable = tablePanel.getTable();
		objTable.setName("Objects");
		objTable.setRowSelectionAllowed(true);

		JPanel container = new JPanel(new BorderLayout());
		container.add(tablePanel, BorderLayout.CENTER);
		var tableFilterPanel = new GhidraTableFilterPanel<>(objTable, timelineModel);
		GDLabel filterLabel = (GDLabel) tableFilterPanel.getComponent(0);
		filterLabel.setText("Table Filter:");
		container.add(tableFilterPanel, BorderLayout.SOUTH);

		timelineModel.addTableModelListener(e -> {

			// for now, there is only one view, so we don't bother to get it

			//this.setTableResultsLabel(model.view.toString() + " (" + model.getRowCount() + " results)");

			if (timelineModel.getRowCount() == 0) {
				return;
			}

			/*for (int i = 0; i < objTable.getColumnCount(); i++) {
				int width = 5;
				for (int j = 0; j < objTable.getRowCount(); j++) {
					TableCellRenderer renderer = objTable.getCellRenderer(j, i);
					Component comp = objTable.prepareRenderer(renderer, j, i);
					width = Math.max(width, comp.getPreferredSize().width);
				}
				// width = Math.min(width);
				TableColumn col = objTable.getColumn(objTable.getColumnName(i));
				if (!objTable.getColumnName(i).equals("Comment")) {
					col.setPreferredWidth(width);
				}
			}*/

		});
		return container;
	}

	public void setView(String ty, Map<String, Long> params) {
		this.timelineModel.view = new ObjectManagerView(ty, params);
		this.timelineModel.reload();
	}
	
	private abstract class ObjectTimelineContextAction extends DockingAction {
		ObjectTimelineComponent provider;
		public ObjectTimelineContextAction(ObjectTimelineComponent provider, String desc, String name) {
			super(desc, name);
			this.provider = provider;
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(context instanceof ObjectTimelineActionContext) {
				return true;
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			if(context instanceof ObjectTimelineActionContext) {
				return true;
			}
			return false;
		}
		
	}
	
	private class AccessesContextAction extends ObjectTimelineContextAction {
		public AccessesContextAction(ObjectTimelineComponent provider) {
			super(provider, "Show accesses in view", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo obj = this.provider.currentObject;
			if(obj == null) {
				return;
			}
			ObjectPhase sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.plugin.timeListingProvider.showObjectPhaseAccessors(obj, sel);
			this.provider.plugin.spaceListingProvider.showObjectPhaseAccesses(obj, sel);
		}
	}

	private class EditTypeContextAction extends ObjectTimelineContextAction {
		public EditTypeContextAction(ObjectTimelineComponent provider) {
			super(provider, "Edit phase type", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectPhase sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			DataType ty = provider.plugin.getUserInputDataType();
			if(ty == null) {
				return;
			}
			this.provider.currentObject.setPhaseType(sel.getStart(), ty);
			this.provider.plugin.madness.updateObject(this.provider.currentObject);
			this.provider.timelineModel.reload();
		}
	}
	
	private class Autostructinator implements MadnessQueryResultListener {
		private MadnessPlugin plugin;
		private ObjectTimelineComponent provider;
		private ObjectPhase currentPhase;
		private ObjectInfo currentObject;
		private boolean addNewType;
		public Autostructinator(MadnessPlugin plugin, ObjectTimelineComponent provider, ObjectInfo obj, ObjectPhase phase, boolean addNewType) {
			this.plugin = plugin;
			this.provider = provider;
			this.currentObject = obj;
			this.currentPhase = phase;
			this.addNewType = addNewType;
		}

		@Override
		public void queryCompleted(List<JSONObject> results, String tag) {
			if(tag.equals("autostruct")) {
				DataType ty = this.currentPhase.getType();
				if(!(ty instanceof Structure)) {
					System.out.println("not a structure: " + ty);
					return;
				}
				Structure struct = (Structure) ty;
				DataTypeManager mgr = plugin.getDataTypeManager();
				if(mgr == null) {
					return;
				}
				int txid = 0;
				txid = mgr.startTransaction("autostruct phase");

				System.out.println("AS RESULTS " + results.toString());
				// results will look like [{offset:..., size:...},...]

				HashSet<Long> prune = new HashSet<>();
				TreeMap<Long, FieldEntry> fields = new TreeMap<>();
				for(int i = 0; i < results.size(); i++) {
					Long offset = results.get(i).getLong("offset");
					Long size = results.get(i).getLong("size");
					if(fields.containsKey(offset)) {
						// add offset to the prune list but add it anyways since we need to know the offset is already present so we can detect duplicates later
						prune.add(offset);
					}
					fields.put(offset, new FieldEntry(offset, size));
				}
				// add overlapping fields to the prune list
				for(Long k1 : fields.navigableKeySet()) {
					FieldEntry f1 = fields.get(k1);
					for(Long k2 : fields.navigableKeySet()) {
						FieldEntry f2 = fields.get(k2);
						if(f1.offset == f2.offset && f1.size == f2.size) continue;
						if((f1.offset <= f2.offset && f2.offset < f1.offset + f1.size) || (f2.offset <= f1.offset && f1.offset < f2.offset + f2.size)) {
							prune.add(k1);
							prune.add(k2);
						}
					}
				}
				// now prune
				for(Long k : prune) {
					System.out.println("PRUNE " + k);
					fields.remove(k);
				}
				
				for(Long k : fields.navigableKeySet()) {
					System.out.println("FIELD " + k);
					FieldEntry field = fields.get(k);
					DataType currentType = struct.getComponentContaining((int)(field.offset)).getDataType();
					if(currentType instanceof Undefined || currentType instanceof DefaultDataType) {
						struct.replaceAtOffset((int)field.offset, field.getDataType(mgr), (int)field.size, String.format("field_0x%x", field.offset), "");
					}
				}

				if(addNewType) {
					mgr.addDataType(struct, null);
				}
				
				mgr.endTransaction(txid, true);
				DataType newType = mgr.getDataType("/"+struct.getName());
				System.out.println("STRUCT " + newType);
				this.currentObject.setPhaseType(this.currentPhase.getStart(), newType);
				
				this.plugin.madness.updateObject(this.currentObject);
				this.provider.timelineModel.reload();
			}
		}
		
	}

	private class AutostructPhaseContextAction extends ObjectTimelineContextAction {
		public AutostructPhaseContextAction(ObjectTimelineComponent provider) {
			super(provider, "Autostruct phase", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo obj = this.provider.currentObject;
			if(obj == null) {
				return;
			}
			ObjectPhase sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}

			Long addrStart = obj.getBase();
			Long addrEnd = obj.getBase() + obj.getSize();
			Long timeStart = sel.getStart();
			Long timeEnd = obj.getPhaseEnd(sel);
			
			String structName = provider.plugin.getUserInputString("new struct name", "new struct name");
			DataTypeManager mgr = plugin.getDataTypeManager();
			if(mgr == null) {
				return;
			}
			int txid = 0;
			DataType check = mgr.getDataType("/" + structName);
			if (check != null) {
				return;
			}
			txid = mgr.startTransaction("autostruct phase");
			StructureDataType struct = new StructureDataType(structName, (int)obj.getSize().longValue());
			sel.setType(struct);
			Autostructinator a = new Autostructinator(this.provider.plugin, this.provider, obj, sel, true);
			String[] params = new String[] {addrStart.toString(), addrEnd.toString(), timeStart.toString(), timeEnd.toString()};
			this.provider.plugin.runQuery("autostruct",  params, a, "autostruct");
		}

	}

	private class AutoFillStructPhaseContextAction extends ObjectTimelineContextAction {
		public AutoFillStructPhaseContextAction(ObjectTimelineComponent provider) {
			super(provider, "Autofull struct phase", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo obj = this.provider.currentObject;
			if(obj == null) {
				return;
			}
			ObjectPhase sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}

			Long addrStart = obj.getBase();
			Long addrEnd = obj.getBase() + obj.getSize();
			Long timeStart = sel.getStart();
			Long timeEnd = obj.getPhaseEnd(sel);
			Autostructinator a = new Autostructinator(this.provider.plugin, this.provider, obj, sel, false);
			String[] params = new String[] {addrStart.toString(), addrEnd.toString(), timeStart.toString(), timeEnd.toString()};
			this.provider.plugin.runQuery("autostruct", params, a, "autostruct");
		}
	}
	
	private class SetStartContextAction extends ObjectTimelineContextAction {
		public SetStartContextAction(ObjectTimelineComponent provider) {
			super(provider, "Set phase start", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectPhase sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			Long tick = provider.plugin.timeListingProvider.getCurrentTick();
			if(tick == null) {
				return;
			}
			this.provider.currentObject.setPhaseStart(sel, tick);
			this.provider.plugin.madness.updateObject(this.provider.currentObject);
			this.provider.timelineModel.reload();
		}
	}

	private class RemovePhaseContextAction extends ObjectTimelineContextAction {
		public RemovePhaseContextAction(ObjectTimelineComponent provider) {
			super(provider, "Remove phase", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectPhase sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.currentObject.removePhase(sel);
			this.provider.plugin.madness.updateObject(this.provider.currentObject);
			this.provider.timelineModel.reload();
		}
	}
	private class NewPhaseStartAtTickContextAction extends ObjectTimelineContextAction {
		public NewPhaseStartAtTickContextAction(ObjectTimelineComponent provider) {
			super(provider, "Create new phase at current tick", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Long tick = provider.plugin.timeListingProvider.getCurrentTick();
			if(tick == null) {
				return;
			}
			DataType ty = provider.plugin.getUserInputDataType();
			if(ty == null) {
				return;
			}
			ObjectPhase phase = new ObjectPhase(tick, ty);
			this.provider.currentObject.addPhase(phase);
			this.provider.plugin.madness.updateObject(this.provider.currentObject);
			this.provider.timelineModel.reload();
		}
	}

	private class NewPhaseNewTypeStartAtTickContextAction extends ObjectTimelineContextAction {
		public NewPhaseNewTypeStartAtTickContextAction(ObjectTimelineComponent provider) {
			super(provider, "Create new phase at current tick", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Long tick = provider.plugin.timeListingProvider.getCurrentTick();
			if(tick == null) {
				return;
			}
			String typename = provider.plugin.getUserInputString("typename", "typename");
			if(typename == null) return;
			DataType ty = new StructureDataType(typename, (int)this.provider.currentObject.getSize().longValue());

			DataTypeManager mgr = provider.plugin.getDataTypeManager();
			if(mgr == null) {
				return;
			}
			int txid = mgr.startTransaction("adding new type");
			mgr.addDataType(ty, null);
			mgr.endTransaction(txid, true);
			DataType newType = mgr.getDataType("/"+ty.getName());
			ObjectPhase phase = new ObjectPhase(tick, newType);
			this.provider.currentObject.addPhase(phase);
			this.provider.plugin.madness.updateObject(this.provider.currentObject);
			this.provider.timelineModel.reload();

		}
	}
	private class Autotypeinator implements MadnessQueryResultListener {
		private MadnessPlugin plugin;
		private ObjectTimelineComponent provider;
		private ObjectInfo currentObject;
		private ObjectPhase currentPhase;

		public Autotypeinator(MadnessPlugin plugin, ObjectTimelineComponent provider, ObjectInfo obj, ObjectPhase phase) {
			this.plugin = plugin;
			this.provider = provider;
			this.currentObject = obj;
			this.currentPhase = phase;
		}

		@Override
		public void queryCompleted(List<JSONObject> results, String tag) {
			if(tag.equals("args")) {
				// results will look like [{starttick,pc,arg_bank,arg_offs},...]
			
				Program p = plugin.getCurrentProgram();
				DataTypeManager dataTypeMan = plugin.getDataTypeManager();
				FunctionManager funcMan = p.getFunctionManager();
			
				boolean openResult = false;
				int txid;

			// 	Change the function parameter to point to the new datatype
				AddressFactory addrFac = p.getAddressFactory();
				AddressSpace addrSpace = addrFac.getDefaultAddressSpace();
			
				DecompInterface decomp = new DecompInterface();
				openResult = decomp.openProgram(p);
			
				// If we fail in loading the program may as well giveup
				if (!openResult) 
				{
					return;
				}

				Pointer ptrType = dataTypeMan.getPointer(this.currentPhase.getType());
				HashMap<Address, HighFunction> decompCache = new HashMap<>();
				for(JSONObject r : results) {
					long pc = r.getBigInteger("pc").longValue();
					long argbank = r.getBigInteger("arg_bank").longValue();
					long argoffs = r.getBigInteger("arg_offs").longValue();
					Function fn = funcMan.getFunctionContaining(addrSpace.getAddress(pc));
					if(fn == null) {
						continue;
					}
					HighFunction highFunc;
					if(decompCache.containsKey(fn.getEntryPoint())) {
						highFunc = decompCache.get(fn.getEntryPoint());
					} else {
						highFunc = decomp.decompileFunction(fn, 0, TaskMonitor.DUMMY).getHighFunction();
						if(highFunc == null) continue;
						decompCache.put(fn.getEntryPoint(), highFunc);
					}
					LocalSymbolMap localSymMap = highFunc.getLocalSymbolMap();
					int numparams = highFunc.getFunctionPrototype().getNumParams();
					Integer idx = null;
					for(int i = 0; i < numparams; i++) {
						HighSymbol param = highFunc.getFunctionPrototype().getParam(i);
						VariableStorage storage = param.getStorage();
						if(storage.isStackStorage() && argbank == 1) {
							long offset = storage.getStackOffset();
							if(offset == argoffs) {
								idx = i;
								break;
							}
						} else if(storage.isRegisterStorage() && argbank == 0) {
							long a = storage.getRegister().getAddress().getOffset();
							if(a == argoffs) {
								idx = i;
								break;
							}
						}
					}
					if(idx == null) continue;
					HighSymbol paramToChange = localSymMap.getParamSymbol(idx);
					try 
					{
						txid = p.startTransaction("Retype function parameter");
						HighFunctionDBUtil.updateDBVariable(paramToChange, paramToChange.getName(), ptrType, SourceType.USER_DEFINED);
						p.endTransaction(txid, true);
					} 
					catch (Exception e) {
						e.printStackTrace();
					}
				}
			} else if(tag.equals("rets")) {
				// now we try to retype function return values
				Program p = plugin.getCurrentProgram();
				DataTypeManager dataTypeMan = plugin.getDataTypeManager();
				FunctionManager funcMan = p.getFunctionManager();
				Pointer ptrType = dataTypeMan.getPointer(this.currentPhase.getType());
				AddressFactory addrFac = p.getAddressFactory();
				AddressSpace addrSpace = addrFac.getDefaultAddressSpace();
				System.out.println("AR RESULTS " + results.toString());
				for(JSONObject r : results) {
					long pc = r.getBigInteger("pc").longValue();
					Function f = funcMan.getFunctionContaining(addrSpace.getAddress(pc));
					Parameter retParam = f.getReturn();
					VariableStorage store = retParam.getVariableStorage();
				// 	currently the database assumes register address 0 is the return address, so we will only retype functions for which this is actually true
					if(store.isRegisterStorage() && store.getRegister().getAddress().getOffset() == 0) { 
						try {
							retParam.setDataType(ptrType, SourceType.USER_DEFINED);
						} catch (Exception e) {
							MadnessPlugin.LOG.error("setRetAsStructPtr Exception changing return type: %s\n", e);
						}
					}
				}
			}
		}
		
	}
	private class AutoPropagatePhasePointerContextAction extends ObjectTimelineContextAction {
		public AutoPropagatePhasePointerContextAction(ObjectTimelineComponent provider) {
			super(provider, "Use phase type for instances", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo obj = this.provider.currentObject;
			if(obj == null) {
				return;
			}
			ObjectPhase sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}

			Long addr = obj.getBase();
			Long timeStart = sel.getStart();
			Long timeEnd = obj.getPhaseEnd(sel);

			String[] params = new String[] {addr.toString(), timeStart.toString(), timeEnd.toString()};
			Autotypeinator a = new Autotypeinator(this.provider.plugin, this.provider, obj, sel);
			this.provider.plugin.runQuery("findptrargs", params, a, "autotypeparams");
			this.provider.plugin.runQuery("findptrrets", params, a, "autotypereturns");
			this.provider.timelineModel.reload();
		}
	}


	private class FieldEntry {
		long offset;
		long size;

		public FieldEntry(long offset, long size) {
			this.offset = offset;
			this.size = size;
		}
		public DataType getDataType(DataTypeManager mgr) {
			switch ((int) this.size) {
				case 1:
					return new CharDataType();
				case 2:
					return new ShortDataType();
				case 4:
					return new IntegerDataType();
				case 8:
					return new LongLongDataType();
			}
			if(this.size < 8) {
				return mgr.getDataType(String.format("/unknown%d", this.size));
			}
			return new ArrayDataType(new CharDataType(), (int)this.size, 1);
		}
	}
}

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

import javax.swing.JComponent;
import javax.swing.JPanel;

import org.json.JSONObject;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
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
import resources.Icons;
import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.View;

public class ObjectManagerProvider extends ComponentProvider implements ActionContextProvider {

	private MadnessPlugin plugin;
	private GhidraThreadedTablePanel<ObjectInfo> tablePanel;
	private GhidraTable objTable;
	public ObjectManagerTableModel model;
	private List<ObjectManagerView> history;
	private int historyCursor;
	
	public ObjectManagerProvider(MadnessPlugin plugin, String description) {
		super(plugin.getTool(), description, plugin.getName());
		this.plugin = plugin;
		this.createDockingActions();
		this.createContextActions();
		this.history = new ArrayList<>();
		this.historyCursor = 0;
	}

	@Override
	public ActionContext getActionContext(MouseEvent ev) {

		ObjectInfo sel = this.getSelectedObject();
		if(sel == null) return null;
		return new ObjectManagerActionContext(this, sel);
	}
	
	private void createContextActions() {
		{
			AccessesContextAction a = new AccessesContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Object accesses"}, null, "space"));
			this.plugin.getTool().addAction(a);
		}
		{
			EditNameContextAction a = new EditNameContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Edit name"}, null, "obj"));
			this.plugin.getTool().addAction(a);
		}
		{
			RemoveContextAction a = new RemoveContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Delete"}, null, "obj"));
			this.plugin.getTool().addAction(a);
		}
		{
			GoToBirthContextAction a = new GoToBirthContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Go to birth tick"}, null, "obj"));
			this.plugin.getTool().addAction(a);
		}
		{
			GoToDeathContextAction a = new GoToDeathContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Go to death tick"}, null, "obj"));
			this.plugin.getTool().addAction(a);
		}
		{
			EditTypeContextAction a = new EditTypeContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Choose phase type"}, null, "type"));
			this.plugin.getTool().addAction(a);
		}
		{
			AutostructContextAction a = new AutostructContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Auto-create new type for phase"}, null, "type"));
			this.plugin.getTool().addAction(a);
		}
		{
			AutoFillStructContextAction a = new AutoFillStructContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Auto-fill existing type for phase"}, null, "type"));
			this.plugin.getTool().addAction(a);
		}
		{
			AutoPropagatePointerContextAction a = new AutoPropagatePointerContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Use phase type for instances"}, null, "type"));
			this.plugin.getTool().addAction(a);
		}
		{
			TargetDataContextAction a = new TargetDataContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Target rectangle"}, null, "nav"));
			this.plugin.getTool().addAction(a);
		}
		
	}
	
	private void createDockingActions() {

		ObjectManagerProvider self = this;
		// Go back in history

		{
			DockingAction undoAction = new DockingAction("Undo", getName()) {
				@Override
				public void actionPerformed(ActionContext arg0) {
					ObjectManagerView v = self.historyBack();
					if (v != null) self.setView(v);
				}
			};
			undoAction.setToolBarData(new ToolBarData(Icons.LEFT_ICON, null));
			undoAction.setEnabled(true);
			this.addLocalAction(undoAction);
		}
		{
			DockingAction redoAction = new DockingAction("Redo", getName()) {
				@Override
				public void actionPerformed(ActionContext arg0) {
					ObjectManagerView v = self.historyForward();
					if (v != null) self.setView(v);
				}
			};
			redoAction.setToolBarData(new ToolBarData(Icons.RIGHT_ICON, null));
			redoAction.setEnabled(true);
			this.addLocalAction(redoAction);
		}
		{
			DockingAction refreshAction = new DockingAction("Refresh", getName()) {
				@Override
				public void actionPerformed(ActionContext arg0) {
					self.plugin.objectCache.refresh();
					self.model.reload();
				}
			};
			refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
			refreshAction.setEnabled(true);
			this.addLocalAction(refreshAction);
		}

	}

	public List<ObjectInfo> getSelectedObjects() {
		int[] rows = this.objTable.getSelectedRows();
		ArrayList<ObjectInfo> sel = new ArrayList<>();
		for(int i = 0; i < rows.length; i++) {
			sel.add(this.model.getRowObject(rows[i]));
		}
		return sel;
	}

	public ObjectInfo getSelectedObject() {		
		int row = this.tablePanel.getTable().getSelectedRow();
		if(row < 0) {
			return null;
		}
		return this.model.getRowObject(row);
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
		model = new ObjectManagerTableModel(this.plugin, this.plugin.getCurrentProgram());
		tablePanel = new GhidraThreadedTablePanel<>(model, 1000);
		objTable = tablePanel.getTable();
		objTable.setName("Objects");
		objTable.setRowSelectionAllowed(true);

		JPanel container = new JPanel(new BorderLayout());
		container.add(tablePanel, BorderLayout.CENTER);
		var tableFilterPanel = new GhidraTableFilterPanel<>(objTable, model);
		GDLabel filterLabel = (GDLabel) tableFilterPanel.getComponent(0);
		filterLabel.setText("Table Filter:");
		container.add(tableFilterPanel, BorderLayout.SOUTH);

		model.addTableModelListener(e -> {
			if (model.getRowCount() == 0) {
				return;
			}
		});
		return container;
	}
	@Override
	public JComponent getComponent() {
		if(tablePanel == null) {
			buildPanel();
		}
		return tablePanel;
	}


	public void historyAdd(ObjectManagerView v) {
		for (int i = this.historyCursor + 1; i < this.history.size();) {
			this.history.remove(i);
		}
		this.history.add(v);
		this.historyCursor++;
	}

	public ObjectManagerView getCurrentHistory() {
		if (this.history.size() == 0)
			return null;
		return this.history.get(this.historyCursor);
	}

	public ObjectManagerView historyBack() {
		if (this.history.size() == 0)
			return null;
		if (this.historyCursor == 0)
			return null;
		this.historyCursor = Math.max(this.historyCursor - 1, 0);
		return this.history.get(this.historyCursor);
	}

	public ObjectManagerView historyForward() {
		if (this.history.size() == 0)
			return null;
		if (this.historyCursor == this.history.size() - 1)
			return null;
		this.historyCursor = Math.min(this.historyCursor + 1, this.history.size() - 1);
		return this.history.get(this.historyCursor);
	}

	public View getView() {
		return this.model.view;
	}

	// makes a new view and sets it (adds to the history)
	public void newView(ObjectManagerView v) {
		this.historyAdd(v);
		this.setView(v);
	}

	// simply sets the view (does not add to history)
	public void setView(ObjectManagerView view) {
		this.model.view = view;
		this.model.reload();
	}

	
	public View exampleView() {
		return new ObjectManagerView();
	}

	public void setView(String ty, Map<String, Long> params) {
		this.model.view = new ObjectManagerView(ty, params);
		this.model.reload();
	}
	
	private abstract class ObjectManagerContextAction extends DockingAction {
		ObjectManagerProvider provider;
		public ObjectManagerContextAction(ObjectManagerProvider provider, String desc, String name) {
			super(desc, name);
			this.provider = provider;
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(context instanceof ObjectManagerActionContext) {
				return true;
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return this.isEnabledForContext(context);
		}
		
	}
	
	private class AccessesContextAction extends ObjectManagerContextAction {
		public AccessesContextAction(ObjectManagerProvider provider) {
			super(provider, "Show accesses in view", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.plugin.timeListingProvider.showObjectAccessors(sel);
			this.provider.plugin.accessListingProvider.showObjectAccesses(sel);
		}
	}
	
	private class EditNameContextAction extends ObjectManagerContextAction {
		public EditNameContextAction(ObjectManagerProvider provider) {
			super(provider, "Edit object name", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			String name = provider.plugin.getUserInputString("name", "name");
			if(name == null) {
				return;
			}
			sel.setName(name);
			this.provider.plugin.madness.updateObject(sel);
			this.provider.model.reload();
		}
	}
	
	private class RemoveContextAction extends ObjectManagerContextAction {
		public RemoveContextAction(ObjectManagerProvider provider) {
			super(provider, "Edit object name", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.plugin.madness.removeObject(sel);
			this.provider.model.reload();
		}
	}
	private class GoToBirthContextAction extends ObjectManagerContextAction {
		public GoToBirthContextAction(ObjectManagerProvider provider) {
			super(provider, "Go to object birth", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.plugin.timeListingProvider.goToTick(sel.getBirth());
		}
	}

	private class GoToDeathContextAction extends ObjectManagerContextAction {
		public GoToDeathContextAction(ObjectManagerProvider provider) {
			super(provider, "Go to object death", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.plugin.timeListingProvider.goToTick(sel.getDeath());
		}
	}
	private class TargetDataContextAction extends ObjectManagerContextAction {
		public TargetDataContextAction(ObjectManagerProvider provider) {
			super(provider, "Target object", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.plugin.dataNavProvider.setStartTick(sel.getBirth());
			this.provider.plugin.dataNavProvider.setEndTick(sel.getDeath());
			this.provider.plugin.dataNavProvider.setStartAddr(sel.getBase());
			this.provider.plugin.dataNavProvider.setEndAddr(sel.getBase()+sel.getSize());
		}
	}

	private class EditTypeContextAction extends ObjectManagerContextAction {
		public EditTypeContextAction(ObjectManagerProvider provider) {
			super(provider, "Edit phase type", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo obj = this.provider.getSelectedObject();
			if(obj == null) {
				return;
			}
			DataType ty = provider.plugin.getUserInputDataType();
			if(ty == null) {
				return;
			}
			this.provider.getSelectedObject().setType(ty);
			this.provider.plugin.madness.updateObject(this.provider.getSelectedObject());
			this.provider.model.reload();
		}
	}
	
	private class Autostructinator implements MadnessQueryResultListener {
		private MadnessPlugin plugin;
		private ObjectManagerProvider provider;
		private ObjectInfo currentObject;
		private boolean addNewType;
		public Autostructinator(MadnessPlugin plugin, ObjectManagerProvider provider, ObjectInfo obj, boolean addNewType) {
			this.plugin = plugin;
			this.provider = provider;
			this.currentObject = obj;
			this.addNewType = addNewType;
		}

		@Override
		public void queryCompleted(List<JSONObject> results, String tag) {
			if(tag.equals("autostruct")) {
				DataType ty = this.currentObject.getType();
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
				this.currentObject.setType(newType);
				
				this.plugin.madness.updateObject(this.currentObject);
				this.provider.model.reload();
			}
		}
		
	}

	private class Autotypeinator implements MadnessQueryResultListener {
		private MadnessPlugin plugin;
		private ObjectManagerProvider provider;
		private ObjectInfo currentObject;

		public Autotypeinator(MadnessPlugin plugin, ObjectManagerProvider provider, ObjectInfo obj) {
			this.plugin = plugin;
			this.provider = provider;
			this.currentObject = obj;
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

				Pointer ptrType = dataTypeMan.getPointer(this.currentObject.getType());
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
				Pointer ptrType = dataTypeMan.getPointer(this.currentObject.getType());
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
	private class AutostructContextAction extends ObjectManagerContextAction {
		public AutostructContextAction(ObjectManagerProvider provider) {
			super(provider, "Autostruct phase", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo obj = this.provider.getSelectedObject();
			if(obj == null) {
				return;
			}

			Long addrStart = obj.getBase();
			Long addrEnd = obj.getBase() + obj.getSize();
			Long timeStart = obj.getBirth();
			Long timeEnd = obj.getDeath();
			
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
			obj.setType(struct);
			Autostructinator a = new Autostructinator(this.provider.plugin, this.provider, obj, true);
			String[] params = new String[] {addrStart.toString(), addrEnd.toString(), timeStart.toString(), timeEnd.toString()};
			this.provider.plugin.runQuery("autostruct",  params, a, "autostruct");
		}

	}

	private class AutoFillStructContextAction extends ObjectManagerContextAction {
		public AutoFillStructContextAction(ObjectManagerProvider provider) {
			super(provider, "Autofull struct phase", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo obj = this.provider.getSelectedObject();
			if(obj == null) {
				return;
			}

			Long addrStart = obj.getBase();
			Long addrEnd = obj.getBase() + obj.getSize();
			Long timeStart = obj.getBirth();
			Long timeEnd = obj.getDeath();
			Autostructinator a = new Autostructinator(this.provider.plugin, this.provider, obj, false);
			String[] params = new String[] {addrStart.toString(), addrEnd.toString(), timeStart.toString(), timeEnd.toString()};
			this.provider.plugin.runQuery("autostruct", params, a, "autostruct");
		}
	}

	private class AutoPropagatePointerContextAction extends ObjectManagerContextAction {
		public AutoPropagatePointerContextAction(ObjectManagerProvider provider) {
			super(provider, "Use type for decompiler variables", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectInfo obj = this.provider.getSelectedObject();
			if(obj == null) {
				return;
			}

			Long addr = obj.getBase();
			Long timeStart = obj.getBirth();
			Long timeEnd = obj.getDeath();

			String[] params = new String[] {addr.toString(), timeStart.toString(), timeEnd.toString()};
			Autotypeinator a = new Autotypeinator(this.provider.plugin, this.provider, obj);
			this.provider.plugin.runQuery("findptrargs", params, a, "autotypeparams");
			this.provider.plugin.runQuery("findptrrets", params, a, "autotypereturns");
			this.provider.model.reload();
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

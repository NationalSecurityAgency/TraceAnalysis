package tracemadness.witnessmanager;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.swing.JComponent;
import javax.swing.JPanel;

import org.json.JSONException;
import org.json.JSONObject;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.label.GDLabel;
import ghidra.program.model.data.DataType;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import resources.Icons;
import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.objectdata.ObjectWitness;
import tracemadness.objectdata.WitnessEvent;
import tracemadness.objectdata.WitnessedObject;
import tracemadness.View;

/*
 * In the workflow 
 *   executed instructions -[1]-> objects with blank types but (perhaps) known sizes -[2]-> better-typed objects -[3]-> better-typed decompiler variables (i.e. hopefully improved decompilation)
 *   
 *   step 1 is executed within TraceMadness by populating this widget with a mapping from static instructions (as they exist within the various modules) 
 *   to what the execution of those instructions suggests about the existence and types of any putative objects that might be in use during the execution
 *   
 *   steps 2 and 3 are assisted by the object manager
 * */

public class WitnessManagerProvider extends ComponentProvider implements ActionContextProvider {

	private MadnessPlugin plugin;
	private GhidraThreadedTablePanel<ObjectWitness> tablePanel;
	private GhidraTable objTable;
	public WitnessManagerTableModel model;
	
	public WitnessManagerProvider(MadnessPlugin plugin, String description) {
		super(plugin.getTool(), description, plugin.getName());
		this.plugin = plugin;
		this.createDockingActions();
		this.createContextActions();
	}

	@Override
	public ActionContext getActionContext(MouseEvent ev) {

		ObjectWitness sel = this.getSelectedObject();
		if(sel == null) return null;
		return new WitnessManagerActionContext(this, sel);
	}
	
	private void createContextActions() {
		{
			HitsContextAction a = new HitsContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Show hits"}, null, "space"));
			this.plugin.getTool().addAction(a);
		}
		{
			RemoveContextAction a = new RemoveContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Delete"}, null, "space"));
			this.plugin.getTool().addAction(a);
		}
		
	}
	public void propose(ArrayList<WitnessedObject> proposals) {
		for(var o : proposals) {
			System.out.println(o);
			ObjectInfo existing = this.plugin.getObjectCache().getObjectAt(o.obj.getBirth(), o.obj.getBase());
			if(existing == null) {
				// our proposed object is a genuinely new object
				// TODO ask the user about these in a batched list instead of just adding them blithely
				System.out.println("new!!!");
				this.plugin.madness.setObject(o.obj);
			}
		}
	}
	private void createDockingActions() {

		WitnessManagerProvider self = this;

		{
			DockingAction calcAction = new DockingAction("Calculate objects", getName()) {
				@Override
				public void actionPerformed(ActionContext arg0) {
					WitnessCalculator calc = new WitnessCalculator(self);
					self.plugin.runQuery("witnessevents", new String[] {}, calc, "events");
					// now calc.proposals is the list of objects we might create
				}
			};
			calcAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
			calcAction.setEnabled(true);
			this.addLocalAction(calcAction);
		}
		{
			DockingAction refreshAction = new DockingAction("Refresh", getName()) {
				@Override
				public void actionPerformed(ActionContext arg0) {
					self.plugin.getObjectCache().refresh();
					self.model.reload();
				}
			};
			refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
			refreshAction.setEnabled(true);
			this.addLocalAction(refreshAction);
		}

	}

	public List<ObjectWitness> getSelectedObjects() {
		int[] rows = this.objTable.getSelectedRows();
		ArrayList<ObjectWitness> sel = new ArrayList<>();
		for(int i = 0; i < rows.length; i++) {
			sel.add(this.model.getRowObject(rows[i]));
		}
		return sel;
	}

	public ObjectWitness getSelectedObject() {		
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

	public WitnessManagerView createView(String ty, Map<String, Long> params) {
		return new WitnessManagerView(ty, params);
	}

	private Component buildTablePanel() {
		model = new WitnessManagerTableModel(this.plugin, this.plugin.getCurrentProgram());
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

	public View getView() {
		return this.model.view;
	}

	// makes a new view and sets it (adds to the history)
	public void newView(WitnessManagerView v) {
		this.setView(v);
	}

	// simply sets the view (does not add to history)
	public void setView(WitnessManagerView view) {
		this.model.view = view;
		this.model.reload();
	}

	
	public View exampleView() {
		return new WitnessManagerView();
	}

	public void setView(String ty, Map<String, Long> params) {
		this.model.view = new WitnessManagerView(ty, params);
		this.model.reload();
	}
	
	private abstract class WitnessManagerContextAction extends DockingAction {
		WitnessManagerProvider provider;
		public WitnessManagerContextAction(WitnessManagerProvider provider, String desc, String name) {
			super(desc, name);
			this.provider = provider;
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(context instanceof WitnessManagerActionContext) {
				return true;
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return this.isEnabledForContext(context);
		}
		
	}
	
	private class HitsContextAction extends WitnessManagerContextAction {
		public HitsContextAction(WitnessManagerProvider provider) {
			super(provider, "Show accesses in view", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectWitness sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			Long pc = this.provider.plugin.moduleMap.getAbsolute(sel.moduleName, sel.offset);
			if(pc != null) {
				this.provider.plugin.timeListingProvider.showAddrWindow(pc, pc);
			}
		}
	}
	
	private class RemoveContextAction extends WitnessManagerContextAction {
		public RemoveContextAction(WitnessManagerProvider provider) {
			super(provider, "Edit object name", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ObjectWitness sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.plugin.madness.removeWitness(sel);
			this.provider.model.reload();
		}
	}
	
	
	private class WitnessCalculator implements MadnessQueryResultListener {
		
		public ArrayList<WitnessedObject> proposals;
		WitnessManagerProvider provider;
		public WitnessCalculator(WitnessManagerProvider provider) {
			this.provider = provider;
		}
		
		@Override
		public void queryCompleted(List<JSONObject> results, String tag) {
			if(tag == "events") {
				this.proposals = new ArrayList<>();
				TreeMap<Long, TreeMap<Long, WitnessedObject>> liveObjects = new TreeMap<>(); // addr -> tick -> obj
				
				ArrayList<WitnessEvent> events = new ArrayList<>();
				for(JSONObject obj : results) {
					try {
						String module = obj.getString("module");
						Long offset = obj.getLong("moduleOffset");
						Long tick = obj.getLong("tick");
						Long addr = obj.getLong("addr");
						
						ObjectWitness  w= plugin.getObjectCache().getWitness(module, offset);
						if(w == null) continue;
						WitnessEvent e = new WitnessEvent(w, tick, addr);
						System.out.println("New event: "+e.toString());
						events.add(e);
					} catch(JSONException e) {
						System.out.println("failed deserialising: " + obj.toString());
					}
				}
				
				// process births first, in tick order, followed by changes, followed by deaths
				events.sort(null);
				
				// iterate through events in time order and create objects for these:
				for(var evt : events) {
					System.out.println("processing event: " + evt.toString());
					Long a = evt.getAddr();
					Long t = evt.tick;
					
					ObjectInfo newObj = null;
					if(evt.witness.type == ObjectWitness.eventType.BIRTH || evt.witness.type == ObjectWitness.eventType.CHANGE) {
						DataType ty = evt.witness.newDataType; 
						newObj = new ObjectInfo(String.format("%d_%d", evt.tick, evt.getAddr()), String.format("my%s", ty.getName()), (long)ty.getLength(), evt.getAddr(), evt.tick, null, ty);
						System.out.println("new object: " + newObj.toString());
					}
					if(!liveObjects.containsKey(evt.getAddr())) liveObjects.put(a,  new TreeMap<>());
					var objsAtAddr = liveObjects.get(evt.getAddr());
					Map.Entry<Long, WitnessedObject> prevObj = objsAtAddr.floorEntry(evt.tick);
					// if there is an object currently live at this tick, we need to kill it now
					if(prevObj != null) {
						System.out.println("found prev object: "+prevObj.getValue().toString());
						WitnessedObject prevValue = prevObj.getValue();
						Long prevDeath = prevValue.obj.getDeath();
						if(prevDeath == null || (prevDeath != null && prevDeath > t)) {
							// if the prev object either alove, or is marked as dead but its death is after that witnessed by this event, then update its death to the current event
							System.out.println("prev object dies now "+t);
							prevObj.getValue().obj.setDeath(evt.tick);
							prevValue.deathWitness = evt.witness;
						}
					} else if (evt.witness.type == ObjectWitness.eventType.CHANGE || evt.witness.type == ObjectWitness.eventType.DEATH){
						System.out.println("death without birth?");
						// technically this is a problem indicating an incomplete set of witnesses, as we are not ending an existing object. Would be good to alert user that there may be another birth witness to identify for this case
					}
					if(evt.witness.type == ObjectWitness.eventType.BIRTH || evt.witness.type == ObjectWitness.eventType.CHANGE) {
						Map.Entry<Long, WitnessedObject> nextObj = objsAtAddr.ceilingEntry(evt.tick);
						// if there is an object live later than this one, we need to set ourselves to die before it starts
						ObjectWitness deathWitness = null;
						if(nextObj != null && newObj != null) {
							System.out.println("next object exists--don't intrude on its life: "+nextObj.getValue().toString());
							newObj.setDeath(nextObj.getKey());
							deathWitness = nextObj.getValue().birthWitness; // our death is thus witnessed by the birth of the new object after us
						}
						// now we can insert ourselves comfortably within the midst of whatever already exists: 
						objsAtAddr.put(evt.tick, new WitnessedObject(evt.witness, deathWitness, newObj));
					}
				}
				for(var a : liveObjects.navigableKeySet()) {
					var objsAtAddr = liveObjects.get(a);
					for(var t : objsAtAddr.navigableKeySet()) {
						proposals.add(objsAtAddr.get(t));
					}
				}
				this.provider.propose(proposals);
			}
		}
		
	}
}

package tracemadness.objectmanager;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.swing.JPanel;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.label.GDLabel;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import resources.Icons;
import tracemadness.MadnessPlugin;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.tabularprovider.View;

public class ObjectManagerProvider extends ComponentProvider implements ActionContextProvider {

	private MadnessPlugin plugin;
	private GhidraThreadedTablePanel<?> tablePanel;
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
			redoAction.setToolBarData(new ToolBarData(Icons.LEFT_ICON, null));
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
		int row = this.objTable.getSelectedRow();
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

			// for now, there is only one view, so we don't bother to get it

			//this.setTableResultsLabel(model.view.toString() + " (" + model.getRowCount() + " results)");

			if (model.getRowCount() == 0) {
				return;
			}

		});
		return container;
	}

	public JPanel getComponent() {
		return buildPanel();
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
			this.provider.plugin.spaceListingProvider.showObjectAccesses(sel);
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

}

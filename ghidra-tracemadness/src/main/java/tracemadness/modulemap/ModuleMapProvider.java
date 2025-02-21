package tracemadness.modulemap;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JPanel;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.label.GDLabel;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import tracemadness.MadnessPlugin;

public class ModuleMapProvider extends ComponentProvider implements ActionContextProvider {

	private MadnessPlugin plugin;
	private GhidraThreadedTablePanel<?> tablePanel;
	private GhidraTable objTable;
	public ModuleMapTableModel model;
	private JPanel mainPanel;
	private ModuleMap map;
	
	public ModuleMapProvider(MadnessPlugin plugin, String description, ModuleMap m) {
		super(plugin.getTool(), description, plugin.getName());
		this.plugin = plugin;
		this.createContextActions();
		this.map = m;
	}

	@Override
	public ActionContext getActionContext(MouseEvent ev) {

		ModuleInfo sel = this.getSelectedObject();
		if(sel == null) return null;
		return new ModuleMapActionContext(this, sel);
	}
	
	private void createContextActions() {
		{
			AccessesContextAction a = new AccessesContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Object accesses"}, null, "space"));
			this.plugin.getTool().addAction(a);
		}
	}
	
	public List<ModuleInfo> getSelectedObjects() {
		int[] rows = this.objTable.getSelectedRows();
		ArrayList<ModuleInfo> sel = new ArrayList<>();
		for(int i = 0; i < rows.length; i++) {
			sel.add(this.model.getRowObject(rows[i]));
		}
		return sel;
	}

	public ModuleInfo getSelectedObject() {		
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

	private Component buildTablePanel() {
		model = new ModuleMapTableModel(this.plugin, this.plugin.getCurrentProgram(), this.map);
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

	@Override
	public JPanel getComponent() {
		if(this.mainPanel == null) {
			this.mainPanel = buildPanel();
		}
		return this.mainPanel;
	}
	
	private abstract class ModuleMapContextAction extends DockingAction {
		ModuleMapProvider provider;
		public ModuleMapContextAction(ModuleMapProvider provider, String desc, String name) {
			super(desc, name);
			this.provider = provider;
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(context instanceof ModuleMapActionContext) {
				return true;
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return this.isEnabledForContext(context);
		}
		
	}
	
	private class AccessesContextAction extends ModuleMapContextAction {
		public AccessesContextAction(ModuleMapProvider provider) {
			super(provider, "Show accesses in view", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ModuleInfo sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			//this.provider.plugin.timeListingProvider.showObjectAccessors(sel);
			//this.provider.plugin.spaceListingProvider.showObjectAccesses(sel);
		}
	}
}

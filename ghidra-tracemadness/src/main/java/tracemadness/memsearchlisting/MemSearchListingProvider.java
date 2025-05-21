package tracemadness.memsearchlisting;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.MouseEvent;
import java.util.ArrayList;

import javax.swing.JComponent;
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

public class MemSearchListingProvider extends ComponentProvider implements ActionContextProvider {

	private MadnessPlugin plugin;
	private GhidraThreadedTablePanel<?> tablePanel;
	private GhidraTable objTable;
	public MemSearchListingTableModel model;
	private boolean forwards;
	private long depth;
	private long index;

	public MemSearchListingProvider(MadnessPlugin plugin, byte[] str) {
		super(plugin.getTool(), "Memory Search Results", plugin.getName());
		this.plugin = plugin;
		this.createContextActions();
		this.model = new MemSearchListingTableModel(this.plugin, str);
	}
	
	@Override
	public ActionContext getActionContext(MouseEvent ev) {
		MemSearchItem sel = this.getSelectedObject();
		if(sel == null) return null;
		return new MemSearchListingActionContext(this, sel);
	}
	
	private void createContextActions() {
		{
			GoToCreateTick a = new GoToCreateTick(this);
			a.setPopupMenuData(new MenuData(new String[] {"Go to buffer creation"}, null, "buffer"));
			this.plugin.getTool().addAction(a);
		}
		{
			GoToDestroyTick a = new GoToDestroyTick(this);
			a.setPopupMenuData(new MenuData(new String[] {"Go to buffer overwrite"}, null, "buffer"));
			this.plugin.getTool().addAction(a);
		}
		{
			GoToAddress a = new GoToAddress(this);
			a.setPopupMenuData(new MenuData(new String[] {"Go to buffer address"}, null, "buffer"));
			this.plugin.getTool().addAction(a);
		}
	}

	public MemSearchItem getSelectedObject() {		
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
		tablePanel = new GhidraThreadedTablePanel<MemSearchItem>(model);
		objTable = tablePanel.getTable();
		objTable.setName("Objects");
		objTable.setRowSelectionAllowed(true);

		JPanel container = new JPanel(new BorderLayout());
		container.add(tablePanel, BorderLayout.CENTER);
		var tableFilterPanel = new GhidraTableFilterPanel<MemSearchItem>(objTable, model);
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

	public JPanel getTablePanel() {
		return buildPanel();
	}

	private abstract class MemSearchItemContextAction extends DockingAction {
		MemSearchListingProvider provider;
		public MemSearchItemContextAction(MemSearchListingProvider provider, String desc, String name) {
			super(desc, name);
			this.provider = provider;
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(context instanceof MemSearchListingActionContext) {
				return true;
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			if(context instanceof MemSearchListingActionContext && (MemSearchListingProvider)(((MemSearchListingActionContext)context).provider) == this.provider) {
				return true;
			}
			return false;
		}
	}
	private class GoToCreateTick extends MemSearchItemContextAction {
		public GoToCreateTick(MemSearchListingProvider provider) {
			super(provider, "Go to buffer creation", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			MemSearchItem sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.plugin.timeListingProvider.goToTick(sel.create_tick);
		}
	}
	private class GoToDestroyTick extends MemSearchItemContextAction {
		public GoToDestroyTick(MemSearchListingProvider provider) {
			super(provider, "Go to buffer overwrite", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			MemSearchItem sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.plugin.timeListingProvider.goToTick(sel.destroy_tick);
			this.provider.plugin.memoryListingProvider.showMemory(sel.address-100, 200, sel.create_tick);
		}
	}
	private class GoToAddress extends MemSearchItemContextAction {
		public GoToAddress(MemSearchListingProvider provider) {
			super(provider, "Go to buffer address", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			MemSearchItem sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.plugin.memoryListingProvider.showMemory(sel.address-100, 200, sel.create_tick);
		}
	}
	

	@Override
	public JComponent getComponent() {
		if(tablePanel == null) {
			buildPanel();
		}
		return tablePanel;
	}
	
}

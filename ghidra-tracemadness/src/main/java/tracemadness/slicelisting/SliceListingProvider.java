package tracemadness.slicelisting;

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

public class SliceListingProvider extends ComponentProvider implements ActionContextProvider {

	private MadnessPlugin plugin;
	private GhidraThreadedTablePanel<?> tablePanel;
	private GhidraTable objTable;
	public SliceListingTableModel model;
	private boolean forwards;
	private long depth;
	private long index;

	public SliceListingProvider(MadnessPlugin plugin, long index, long depth, boolean forwards) {
		super(plugin.getTool(), "Slice Listing", plugin.getName());
		this.plugin = plugin;
		this.index = index;
		this.depth = depth;
		this.forwards = forwards;
		this.createContextActions();
		this.model = new SliceListingTableModel(this.plugin, this.index, this.depth, this.forwards);
	}
	
	@Override
	public ActionContext getActionContext(MouseEvent ev) {
		SliceItem sel = this.getSelectedObject();
		if(sel == null) return null;
		return new SliceListingActionContext(this, sel);
	}
	
	private void createContextActions() {
		{
			ShowPathContextAction a = new ShowPathContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Show Path"}, null, "slice"));
			this.plugin.getTool().addAction(a);
		}
	}

	public SliceItem getSelectedObject() {		
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
		tablePanel = new GhidraThreadedTablePanel<SliceItem>(model);
		objTable = tablePanel.getTable();
		objTable.setName("Objects");
		objTable.setRowSelectionAllowed(true);

		JPanel container = new JPanel(new BorderLayout());
		container.add(tablePanel, BorderLayout.CENTER);
		var tableFilterPanel = new GhidraTableFilterPanel<SliceItem>(objTable, model);
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

	private abstract class SliceItemContextAction extends DockingAction {
		SliceListingProvider provider;
		public SliceItemContextAction(SliceListingProvider provider, String desc, String name) {
			super(desc, name);
			this.provider = provider;
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(context instanceof SliceListingActionContext) {
				return true;
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			if(context instanceof SliceListingActionContext && (SliceListingProvider)(((SliceListingActionContext)context).provider) == this.provider) {
				return true;
			}
			return false;
		}
	}
	private class ShowPathContextAction extends SliceItemContextAction {
		public ShowPathContextAction(SliceListingProvider provider) {
			super(provider, "Show path", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			SliceItem sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			ArrayList<Long> indices = new ArrayList<Long>();
			for(int i = 0; i < sel.path.length; i++) {
				indices.add(sel.path[i]);
			}
			this.provider.plugin.timeListingProvider.showPath(indices);
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

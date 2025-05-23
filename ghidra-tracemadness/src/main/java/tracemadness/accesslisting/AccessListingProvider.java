package tracemadness.accesslisting;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.GroupLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;

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
import tracemadness.View;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.timelisting.TimeListingLayoutModel;

/*
 * In the workflow 
 *   executed instructions -[1]-> objects with blank types but (perhaps) known sizes -[2]-> better-typed objects -[3]-> better-typed decompiler variables (i.e. hopefully improved decompilation)
 *   
 *   step 1 is assisted by the witness manager
 *   
 *   step 2 is executed within TraceMadness by populating this widget with objects (whether manually or by collecting witnesses) and then using this   
 *   tool to auto-populate the fields of the structure types associated with all the objects in this list
 *   
 *   step 3 is executed within TraceMadness by using this widget to propagate to all decompiler variables that take on (at any point in
 *   the trace) the value that corresponds to the base address of a then-live object from the list, the then-type of that object
 * */
public class AccessListingProvider extends ComponentProvider implements ActionContextProvider {

	private MadnessPlugin plugin;
	private GhidraThreadedTablePanel<AnnotatedAccessEvent> tablePanel;
	private GhidraTable objTable;
	public AccessListingTableModel model;
	private List<AccessListingView> history;
	private int historyCursor;
	boolean guiReady;
	JPanel mainPanel;
	JPanel tableContainer;
	JLabel statusLabel;
	public JLabel objStatusLabel;
	public JLabel fieldStatusLabel;
	public enum DISPLAY_MODE {VALID, INVALID, ALL}
	public DISPLAY_MODE objDisplay;
	public DISPLAY_MODE fieldDisplay;
	
	public AccessListingProvider(MadnessPlugin plugin, String description) {
		super(plugin.getTool(), description, plugin.getName());
		guiReady = false;
		this.plugin = plugin;
		this.createDockingActions();
		this.createContextActions();
		this.history = new ArrayList<>();
		this.historyCursor = 0;
		this.model = new AccessListingTableModel(this.plugin, this, new AccessListingView());
		this.model.loadSpace();
		tablePanel = new GhidraThreadedTablePanel<>(model, 1000);
		buildPanel();
		this.setObjMode(DISPLAY_MODE.ALL);
		this.setFieldMode(DISPLAY_MODE.ALL);
		guiReady = true;
	}
	public void setObjMode(DISPLAY_MODE newMode) {
		this.objDisplay = newMode;
		this.model.reload();
	}
	public void setFieldMode(DISPLAY_MODE newMode) {
		this.fieldDisplay = newMode;
		this.model.reload();
	}

	@Override
	public ActionContext getActionContext(MouseEvent ev) {

		AnnotatedAccessEvent sel = this.getSelectedObject();
		if(sel == null) return null;
		return new AccessListingActionContext(this, sel);
	}
	
	private void createContextActions() {
		{
			AccessesContextAction a = new AccessesContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Object accesses"}, null, "space"));
			this.plugin.getTool().addAction(a);
		}
		{
			GoToContextAction a = new GoToContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Go to access"}, null, "time"));
			this.plugin.getTool().addAction(a);
		}
		
	}
	
	private void createDockingActions() {

		AccessListingProvider self = this;
		// Go back in history

		{
			DockingAction undoAction = new DockingAction("Undo", getName()) {
				@Override
				public void actionPerformed(ActionContext arg0) {
					AccessListingView v = self.historyBack();
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
					AccessListingView v = self.historyForward();
					if (v != null) self.setView(v);
				}
			};
			redoAction.setToolBarData(new ToolBarData(Icons.RIGHT_ICON, null));
			redoAction.setEnabled(true);
			this.addLocalAction(redoAction);
		}
		{
			DockingAction refreshAction = new DockingAction("All", getName()) {
				@Override
				public void actionPerformed(ActionContext arg0) {
					self.setView(new AccessListingView(AccessListingView.VIEW_TYPE.ALL_VIEW.name(), new HashMap<>()));
				}
			};
			refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
			refreshAction.setEnabled(true);
			this.addLocalAction(refreshAction);
		}

	}

	public List<AnnotatedAccessEvent> getSelectedObjects() {
		int[] rows = this.objTable.getSelectedRows();
		ArrayList<AnnotatedAccessEvent> sel = new ArrayList<>();
		for(int i = 0; i < rows.length; i++) {
			sel.add(this.model.getRowObject(rows[i]));
		}
		return sel;
	}

	public AnnotatedAccessEvent getSelectedObject() {		
		int row = this.tablePanel.getTable().getSelectedRow();
		if(row < 0) {
			return null;
		}
		return this.model.getRowObject(row);
	}
	public void setStatus(String status) {
		this.statusLabel.setText(status);
	}
	
	private void buildPanel() {
		AccessListingProvider self = this;
		
		mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout());

		JPanel statusPanel = new JPanel();
		GroupLayout layout = new GroupLayout(statusPanel);
		statusPanel.setLayout(layout);
		statusLabel = new JLabel("Status:");

		ButtonGroup fieldButtonGroup = new ButtonGroup();
		JRadioButton fieldOnlyValid = new JRadioButton();
		JRadioButton fieldOnlyInvalid = new JRadioButton();
		JRadioButton fieldAll = new JRadioButton();
		JLabel fieldOnlyValidLabel = new JLabel("Only valid fields");
		JLabel fieldOnlyInvalidLabel = new JLabel("Only invalid fields");
		JLabel fieldAllLabel = new JLabel("All fields");
		fieldStatusLabel = new JLabel("");
		fieldButtonGroup.add(fieldAll);
		fieldButtonGroup.add(fieldOnlyValid);
		fieldButtonGroup.add(fieldOnlyInvalid);
		
		ButtonGroup objButtonGroup = new ButtonGroup();
		JLabel objOnlyValidLabel = new JLabel("Only valid objects");
		JLabel objOnlyInvalidLabel = new JLabel("Only invalid objects");
		JLabel objAllLabel = new JLabel("All objects");
		objStatusLabel = new JLabel("");
		JRadioButton objOnlyValid = new JRadioButton();
		JRadioButton objOnlyInvalid = new JRadioButton();
		JRadioButton objAll = new JRadioButton();
		objButtonGroup.add(objAll);
		objButtonGroup.add(objOnlyValid);
		objButtonGroup.add(objOnlyInvalid);

		layout.setAutoCreateGaps(true);
		layout.setAutoCreateContainerGaps(true);

		layout.setHorizontalGroup(layout.createSequentialGroup()
				.addGroup(layout.createParallelGroup()
						.addComponent(statusLabel)
						.addComponent(objStatusLabel)
						.addComponent(fieldStatusLabel))
				.addGroup(layout.createParallelGroup()
						.addComponent(objAllLabel)
						.addComponent(fieldAllLabel))
				.addGroup(layout.createParallelGroup()
						.addComponent(objAll)
						.addComponent(fieldAll))
				.addGroup(layout.createParallelGroup()
						.addComponent(objOnlyValidLabel)
						.addComponent(fieldOnlyValidLabel))
				.addGroup(layout.createParallelGroup()
						.addComponent(objOnlyValid)
						.addComponent(fieldOnlyValid))
				.addGroup(layout.createParallelGroup()
						.addComponent(objOnlyInvalidLabel)
						.addComponent(fieldOnlyInvalidLabel))
				.addGroup(layout.createParallelGroup()
						.addComponent(objOnlyInvalid)
						.addComponent(fieldOnlyInvalid)));
		layout.setVerticalGroup(layout.createSequentialGroup()
				.addGroup(layout.createParallelGroup()
						.addComponent(statusLabel))
				.addGroup(layout.createParallelGroup()
						.addComponent(objStatusLabel)
						.addComponent(objAllLabel)
						.addComponent(objAll)
						.addComponent(objOnlyValidLabel)
						.addComponent(objOnlyValid)
						.addComponent(objOnlyInvalidLabel)
						.addComponent(objOnlyInvalid))
				.addGroup(layout.createParallelGroup()
						.addComponent(fieldStatusLabel)
						.addComponent(fieldAllLabel)
						.addComponent(fieldAll)
						.addComponent(fieldOnlyValidLabel)
						.addComponent(fieldOnlyValid)
						.addComponent(fieldOnlyInvalidLabel)
						.addComponent(fieldOnlyInvalid)));
		objAll.addActionListener(new AbstractAction("All objects") { public void actionPerformed(ActionEvent ev) { self.setObjMode(DISPLAY_MODE.ALL); } });
		objOnlyValid.addActionListener(new AbstractAction("Valid objects") { public void actionPerformed(ActionEvent ev) { self.setObjMode(DISPLAY_MODE.VALID); } });
		objOnlyInvalid.addActionListener(new AbstractAction("Invalid objects") { public void actionPerformed(ActionEvent ev) { self.setObjMode(DISPLAY_MODE.INVALID); } });
		fieldAll.addActionListener(new AbstractAction("All fields") { public void actionPerformed(ActionEvent ev) { self.setObjMode(DISPLAY_MODE.ALL); } });
		fieldOnlyValid.addActionListener(new AbstractAction("Valid fields") { public void actionPerformed(ActionEvent ev) { self.setObjMode(DISPLAY_MODE.VALID); } });
		fieldOnlyInvalid.addActionListener(new AbstractAction("Invalid fields") { public void actionPerformed(ActionEvent ev) { self.setObjMode(DISPLAY_MODE.INVALID); } });
		
		
		statusPanel.add(statusLabel);
		
		mainPanel.add(statusPanel, BorderLayout.NORTH);
		
		tableContainer = new JPanel(new BorderLayout());
		objTable = tablePanel.getTable();
		objTable.setName("Objects");
		objTable.setRowSelectionAllowed(true);
		tableContainer.add(tablePanel, BorderLayout.CENTER);
		var tableFilterPanel = new GhidraTableFilterPanel<>(objTable, model);
		GDLabel filterLabel = (GDLabel) tableFilterPanel.getComponent(0);
		filterLabel.setText("Table Filter:");
		tableContainer.add(tableFilterPanel, BorderLayout.SOUTH);
		
		mainPanel.add(tableContainer, BorderLayout.CENTER);
	}

	public AccessListingView createView(String ty, Map<String, Long> params) {
		return new AccessListingView(ty, params);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}


	public void historyAdd(AccessListingView v) {
		for (int i = this.historyCursor + 1; i < this.history.size();) {
			this.history.remove(i);
		}
		this.history.add(v);
		this.historyCursor++;
	}

	public AccessListingView getCurrentHistory() {
		if (this.history.size() == 0)
			return null;
		return this.history.get(this.historyCursor);
	}

	public AccessListingView historyBack() {
		if (this.history.size() == 0)
			return null;
		if (this.historyCursor == 0)
			return null;
		this.historyCursor = Math.max(this.historyCursor - 1, 0);
		return this.history.get(this.historyCursor);
	}

	public AccessListingView historyForward() {
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
	public void newView(AccessListingView v) {
		this.historyAdd(v);
		this.setView(v);
	}

	// simply sets the view (does not add to history)
	public void setView(AccessListingView view) {
		this.model.setView(view);
		/*this.model = new AccessListingTableModel(this.plugin, this, view);
		tablePanel = new GhidraThreadedTablePanel<>(model, 1000);
		

		tableContainer = new JPanel(new BorderLayout());
		objTable = tablePanel.getTable();
		objTable.setName("Objects");
		objTable.setRowSelectionAllowed(true);
		tableContainer.add(tablePanel, BorderLayout.CENTER);
		var tableFilterPanel = new GhidraTableFilterPanel<>(objTable, model);
		GDLabel filterLabel = (GDLabel) tableFilterPanel.getComponent(0);
		filterLabel.setText("Table Filter:");
		tableContainer.add(tableFilterPanel, BorderLayout.SOUTH);
		mainPanel.removeAll();
		mainPanel.add(tableContainer, BorderLayout.CENTER);*/
	}
	public void refresh() {
		this.mainPanel.repaint();
	}
	
	public View exampleView() {
		return new AccessListingView();
	}

	//public void setView(String ty, Map<String, Long> params) {
	//	this.model.view = new AccessListingView(ty, params);
	//	this.model.reload();
	//}
	//---------------------------------------------------------------
	// Here begin the API functions to call the  
	public void showAccessesInRange(long start, long end) {
		HashMap<String, Long> params = new HashMap<>();
		params.put(AccessListingView.VIEW_PARAM.ADDR_START.name(), start);
		params.put(AccessListingView.VIEW_PARAM.ADDR_END.name(), end);
		this.newView(new AccessListingView(AccessListingView.VIEW_TYPE.ADDR_WINDOW_VIEW.name(), params));
	}
	public void showAccessesInRect(long startTick, long endTick, long startAddr, long endAddr) {
		HashMap<String, Long> params = new HashMap<>();
		params.put(AccessListingView.VIEW_PARAM.ADDR_START.name(), startAddr);
		params.put(AccessListingView.VIEW_PARAM.ADDR_END.name(), endAddr);
		params.put(AccessListingView.VIEW_PARAM.TIME_START.name(), startTick);
		params.put(AccessListingView.VIEW_PARAM.TIME_END.name(), endTick);
		this.newView(new AccessListingView(AccessListingView.VIEW_TYPE.ADDR_TIME_WINDOW_VIEW.name(), params));
	}
	public void showAccessesInPCRect(long startTick, long endTick, long startAddr, long endAddr) {
		HashMap<String, Long> params = new HashMap<>();
		params.put(AccessListingView.VIEW_PARAM.ADDR_START.name(), startAddr);
		params.put(AccessListingView.VIEW_PARAM.ADDR_END.name(), endAddr);
		params.put(AccessListingView.VIEW_PARAM.TIME_START.name(), startTick);
		params.put(AccessListingView.VIEW_PARAM.TIME_END.name(), endTick);
		this.newView(new AccessListingView(AccessListingView.VIEW_TYPE.PC_TIME_WINDOW_VIEW.name(), params));
	}
	public void showAccessesByPCRange(long start, long end) {
		HashMap<String, Long> params = new HashMap<>();
		params.put(AccessListingView.VIEW_PARAM.ADDR_START.name(), start);
		params.put(AccessListingView.VIEW_PARAM.ADDR_END.name(), end);
		this.newView(new AccessListingView(AccessListingView.VIEW_TYPE.PC_WINDOW_VIEW.name(), params));
	}
	public void showObjectAccesses(ObjectInfo obj) {
		HashMap<String, Long> params = new HashMap<>();
		long size = obj.getSize();
		params.put(AccessListingView.VIEW_PARAM.ADDR_START.name(), obj.getBase());
		params.put(AccessListingView.VIEW_PARAM.ADDR_END.name(), obj.getBase()+size);
		params.put(AccessListingView.VIEW_PARAM.TIME_START.name(), obj.getBirth());
		params.put(AccessListingView.VIEW_PARAM.TIME_END.name(), obj.getDeath());
		this.newView(new AccessListingView(AccessListingView.VIEW_TYPE.ADDR_TIME_WINDOW_VIEW.name(), params));
	}
	public void showAccessesInTimeWindow(long start, long end) {
		HashMap<String, Long> params = new HashMap<>();
		params.put(AccessListingView.VIEW_PARAM.TIME_START.name(), start);
		params.put(AccessListingView.VIEW_PARAM.TIME_END.name(), end);
		this.newView(new AccessListingView(AccessListingView.VIEW_TYPE.TIME_WINDOW_VIEW.name(), params));
	}
	
	//---------------------------------------------------------------
	private abstract class AccessListingContextAction extends DockingAction {
		AccessListingProvider provider;
		public AccessListingContextAction(AccessListingProvider provider, String desc, String name) {
			super(desc, name);
			this.provider = provider;
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(context instanceof AccessListingActionContext) {
				return true;
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return this.isEnabledForContext(context);
		}
		
	}

	private class AccessesContextAction extends AccessListingContextAction {
		public AccessesContextAction(AccessListingProvider provider) {
			super(provider, "Object accessors", provider.plugin.getName());
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(!super.isEnabledForContext(context)) {
				return false;
			}AnnotatedAccessEvent sel = this.provider.getSelectedObject();
			if(sel == null || sel.obj == null) {
				return false;
			}
			return true;
		}
		
		@Override
		public void actionPerformed(ActionContext context) {
			AnnotatedAccessEvent sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			if(sel.obj == null) {
				return;
			}
			this.provider.plugin.timeListingProvider.showObjectAccessors(sel.obj);
		}
	}
	private class GoToContextAction extends AccessListingContextAction {
		public GoToContextAction(AccessListingProvider provider) {
			super(provider, "Go to access", provider.plugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			AnnotatedAccessEvent sel = this.provider.getSelectedObject();
			if(sel == null) {
				return;
			}
			this.provider.plugin.timeListingProvider.goToTick(sel.event.getTick());
		}
	}
	
}

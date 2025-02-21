package tracemadness.timelisting;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.GridLayout;
import java.awt.Rectangle;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.json.JSONObject;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.app.context.ListingActionContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.Swing;
import resources.Icons;
import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;
import tracemadness.listingfield.SpacetimeOperationField;
import tracemadness.listingfield.SpacetimePCField;
import tracemadness.listingfield.SpacetimeTickField;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.objectdata.ObjectPhase;
import tracemadness.slicelisting.SliceListingProvider;
import tracemadness.spacelisting.SpaceListingView;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.listener.FieldLocationListener;
import docking.widgets.fieldpanel.listener.FieldMouseListener;
import docking.widgets.fieldpanel.listener.FieldSelectionListener;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import generic.theme.GIcon;

public class TimeListingProvider extends ComponentProvider implements FieldLocationListener, FieldMouseListener,
		FieldSelectionListener, ActionContextProvider, HoverProvider, BackgroundColorModel, MadnessQueryResultListener {

	private JComponent mainPanel;
	private IndexedScrollPane scroller; // The scroll pane containing the listing panel
	private FieldPanel listingPanel; // the panel for the main instruction listing
	private JLabel fullFieldFooter; // the footer for displaying the full versions of clipped text
	private JLabel currentViewFooter; // the footer for displaying the full versions of clipped text
	private LayoutModel model;
	private MadnessPlugin plugin;
	private TimeListingView view;
	private Font font;
	private FontMetrics fontMetrics;
	private DecompInterface decomp;
	private HashMap<Address, HighFunction> decompCache;

	private ToggleDockingAction navigationOutgoingAction;
	private ToggleDockingAction navigationIncomingAction;
	private ToggleDockingAction functionDisplayToggleAction;
	private ToggleDockingAction instructionDisplayToggleAction;
	private List<TimeListingView> history;
	private int historyCursor;

	public TimeListingProvider(MadnessPlugin plugin, String name) {
		// TODO what is the "owner" third parameter here supposed to be?
		super(plugin.getTool(), name, name);
		this.plugin = plugin;
		this.mainPanel = new JPanel();
		font = new Font("Monospaced", Font.PLAIN, 14);
		this.mainPanel.setFont(font);
		this.fontMetrics = this.mainPanel.getFontMetrics(font);

		// init the decompiler (which we will use to generate function entries in the
		// layout)
		decompCache = new HashMap<Address, HighFunction>();
		decomp = new DecompInterface();

		// init the history
		this.view = new TimeListingView();
		this.history = new ArrayList<>();
		this.historyAdd(this.view);

		this.model = new TimeListingLayoutModel(this.plugin, this, this.view, this.fontMetrics,
				this.decomp, this.decompCache, true, true);
		this.listingPanel = new FieldPanel(this.model, "Time listing");
		this.listingPanel.setFont(font);
		this.listingPanel.setBackgroundColorModel(this);

		// Add the click listeners
		setupMouseListeners();

		// Add the context menu items and ensure that right clicks in this provider's
		// component happen in the TimeListingActionContext context
		plugin.getTool().registerDefaultContextProvider(TimeListingActionContext.class, this);
		createContextActions();

		// Add the docking actions
		createDockingActions();

		// Set the hover handler
		this.listingPanel.setHoverProvider(this);

		((TimeListingLayoutModel)this.model).loadInstructions();
		// Make the GUI
		buildTimeListingPanel();
	}

	public Long getCurrentTick() {
		BigInteger index = this.listingPanel.getCursorLocation().getIndex();
		return ((TimeListingLayoutModel) this.model).getTick(index);
	}

	public void historyAdd(TimeListingView v) {
		for (int i = this.historyCursor + 1; i < this.history.size();) {
			this.history.remove(i);
		}
		if (this.listingPanel != null && this.history.size() > 0) {
			// set the previous view to have the current tick as its location
			TimeListingView prev = this.history.get(this.history.size()-1);
			prev.lastTick = ((TimeListingLayoutModel) this.model).getTick(this.listingPanel.getCursorLocation().getIndex());
		}
		this.history.add(v);
		this.historyCursor++;
	}

	public TimeListingView getCurrentHistory() {
		if (this.history.size() == 0)
			return null;
		return this.history.get(this.historyCursor);
	}

	public TimeListingView historyBack() {
		if (this.history.size() == 0)
			return null;
		if (this.historyCursor == 0)
			return null;
		this.historyCursor = Math.max(this.historyCursor - 1, 0);
		return this.history.get(this.historyCursor);
	}

	public TimeListingView historyForward() {
		if (this.history.size() == 0)
			return null;
		if (this.historyCursor == this.history.size() - 1)
			return null;
		this.historyCursor = Math.min(this.historyCursor + 1, this.history.size() - 1);
		return this.history.get(this.historyCursor);
	}

	public TimeListingView getView() {
		return this.view;
	}

	// makes a new view and sets it (adds to the history)
	public void newView(TimeListingView v) {
		this.historyAdd(v);
		this.setView(v);
	}

	// simply sets the view (does not add to history)
	public void setView(TimeListingView view) {
		this.view = view;
		currentViewFooter.setText("Now viewing: " + this.view.toString());
		this.model = new TimeListingLayoutModel(this.plugin, this, view, this.fontMetrics, this.decomp,
				this.decompCache, this.functionDisplayToggleAction.isSelected(),
				this.instructionDisplayToggleAction.isSelected());

		((TimeListingLayoutModel)this.model).loadInstructions();
	}
	
	public void refresh() {
		this.listingPanel.setLayoutModel(this.model);
		this.scroller.indexModelChanged();
		if (this.view.lastTick != null && this.listingPanel != null) {
			System.out.println("scrolling to tick " + this.view.lastTick);
			BigInteger idx = ((TimeListingLayoutModel) this.model).getTickIndex(this.view.lastTick);
			if (idx != null) {
				this.listingPanel.setCursorPosition(BigInteger.ZERO, 0, 0, 0);
				this.listingPanel.scrollToCursor();
				this.listingPanel.setCursorPosition(idx, 0, 0, 0);
				int visibleIndices = this.listingPanel.getVisibleEndLayout().getIndex().subtract(this.listingPanel.getVisibleStartLayout().getIndex()).intValue();
				this.listingPanel.scrollToCursor();
				for (int i = 0; i < visibleIndices / 2; i++) {
					this.listingPanel.scrollLineDown();
				}
			}
		}
	}

	public void dispose() {
		plugin.getTool().unregisterDefaultContextProvider(TimeListingActionContext.class, this);
	}

	// Customize GUI
	private void buildTimeListingPanel() {
		this.mainPanel.setLayout(new BorderLayout());
		this.scroller = new IndexedScrollPane(this.listingPanel);
		// scroller.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		// scroller.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		this.mainPanel.add(scroller, BorderLayout.CENTER);

		this.fullFieldFooter = new JLabel("");
		this.currentViewFooter = new JLabel("");
		JPanel footerPanel = new JPanel(new GridLayout(1, 2));
		footerPanel.add(currentViewFooter);
		footerPanel.add(fullFieldFooter);

		this.mainPanel.add(footerPanel, BorderLayout.SOUTH);
	}

	private void setupMouseListeners() {
		this.listingPanel.addFieldLocationListener(this);
		this.listingPanel.addFieldMouseListener(this);
		this.listingPanel.addFieldSelectionListener(this);
	}

	private void createDockingActions() {

		TimeListingProvider self = this;
		
		// Go to next tick
		DockingAction gotoNextAction = new DockingAction("Go To Next Tick", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				Field f = self.listingPanel.getCurrentField();
				if (f != null && f instanceof SpacetimeTickField) {
					SpacetimeTickField sf = (SpacetimeTickField) f;
					self.goToTick(sf.getTick()+1);
				}
			}
		};
		gotoNextAction.setToolBarData(new ToolBarData(new GIcon("icon.down"), null));
		gotoNextAction.setEnabled(true);
		this.addLocalAction(gotoNextAction);
		
		// Go to prev tick
		DockingAction gotoPrevAction = new DockingAction("Go To Previous Tick", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				Field f = self.listingPanel.getCurrentField();
				if (f != null && f instanceof SpacetimeTickField) {
					SpacetimeTickField sf = (SpacetimeTickField) f;
					self.goToTick(sf.getTick()-1);
				}
			}
		};
		gotoPrevAction.setToolBarData(new ToolBarData(new GIcon("icon.up"), null));
		gotoPrevAction.setEnabled(true);
		this.addLocalAction(gotoPrevAction);
		
		// Go to callsite
		DockingAction gotoCallsiteAction = new DockingAction("Go To Function Callsite", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				Field f = self.listingPanel.getCurrentField();
				if (f != null && f instanceof SpacetimeTickField) {
					SpacetimeTickField sf = (SpacetimeTickField) f;
					String[] params = { String.format("%d", sf.getTick()) }; // TODO filters
					try {
						self.listingPanel.clearHighlight();
						plugin.runQuery("functioninfo", params, self, "gotoCallsite");
					} catch(Exception e) {
						// do nothing
					}
				}
			}
		};
		gotoCallsiteAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.symboltree.node.function"), null));
		gotoCallsiteAction.setEnabled(true);
		this.addLocalAction(gotoCallsiteAction);

		// Go to return
		DockingAction gotoReturnAction = new DockingAction("Go To Function Return", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				Field f = self.listingPanel.getCurrentField();
				if (f != null && f instanceof SpacetimeTickField) {
					SpacetimeTickField sf = (SpacetimeTickField) f;
					String[] params = { String.format("%d", sf.getTick()) };
					try {
						self.listingPanel.clearHighlight();
						plugin.runQuery("functioninfo", params, self, "gotoReturn"); // result handled in queryCompleted
					} catch(Exception e) {
						// do nothing
					}
				}
			}
		};
		gotoReturnAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.symboltree.node.function.thunk"), null));
		gotoReturnAction.setEnabled(true);
		this.addLocalAction(gotoReturnAction);
		
		// Go to tick
		DockingAction gotoAction = new DockingAction("Go To Tick", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				Long tick = self.plugin.getUserInputLong("tick", "tick");
				if (tick != null) {
					self.goToTick(tick);
				}
			}
		};
		gotoAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.datatypes.filter.pointers.off"), null));
		gotoAction.setEnabled(true);
		this.addLocalAction(gotoAction);
		
		// Go back in history
		DockingAction undoHistoryAction = new DockingAction("Back", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				TimeListingView v = self.historyBack();
				if (v != null)
					self.setView(v);
			}
		};
		undoHistoryAction.setToolBarData(new ToolBarData(Icons.LEFT_ICON, null));
		undoHistoryAction.setEnabled(true);
		this.addLocalAction(undoHistoryAction);

		// Go forwards in history
		DockingAction redoHistoryAction = new DockingAction("Forward", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				TimeListingView v = self.historyForward();
				if (v != null)
					self.setView(v);
			}
		};
		redoHistoryAction.setToolBarData(new ToolBarData(Icons.RIGHT_ICON, null));
		redoHistoryAction.setEnabled(true);
		this.addLocalAction(redoHistoryAction);

		// Toggle the display of functions
		functionDisplayToggleAction = new ToggleDockingAction("Toggle Function Display", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				System.out.println("instoggle: " + this.isSelected());
				self.setView(self.view);
			}
		};
		functionDisplayToggleAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.navigation.function"), null));
		functionDisplayToggleAction.setEnabled(true);
		functionDisplayToggleAction.setSelected(true);
		this.addLocalAction(functionDisplayToggleAction);

		// Toggle the display of instructions
		instructionDisplayToggleAction = new ToggleDockingAction("Toggle Instruction Display", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				self.setView(self.view);
			}
		};
		instructionDisplayToggleAction
				.setToolBarData(new ToolBarData(new GIcon("icon.plugin.navigation.instruction"), null));
		instructionDisplayToggleAction.setEnabled(true);
		instructionDisplayToggleAction.setSelected(true);
		this.addLocalAction(instructionDisplayToggleAction);

		// Toggling outgoing anchor updates
		navigationOutgoingAction = new ToggleDockingAction("Toggle Outgoing Synchanges", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				// No code needed here - toggling automatically updates
				// navigationOutgoingAction.isSelected() which we use elsewhere to make
				// decisions
			}
		};
		navigationOutgoingAction.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_OUTGOING_EVENT_ICON, null));
		navigationOutgoingAction.setEnabled(true);
		navigationOutgoingAction.setSelected(true);
		this.addLocalAction(navigationOutgoingAction);

		// Toggling incoming anchor updates
		navigationIncomingAction = new ToggleDockingAction("Toggle Incoming Sync Changes", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				// No code needed here - toggling automatically updates
				// navigationIncomingAction.isSelected() which we use elsewhere to make
				// decisions
			}
		};
		navigationIncomingAction.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON, null));
		navigationIncomingAction.setEnabled(true);
		navigationIncomingAction.setSelected(true);
		this.addLocalAction(navigationIncomingAction);

	}

	private void createContextActions() {
		/*
		 * { TimeListingContextAction a = new TimeListingContextAction(this);
		 * a.setPopupMenuData(new MenuData(new String[] {"Debug context"}, null,
		 * "debug")); this.plugin.getTool().addAction(a); }
		 */
		{
			AccessesContextAction as = new AccessesContextAction(this);
			as.setPopupMenuData(new MenuData(new String[] { "Show memory accesses" }, null, "space"));
			this.plugin.getTool().addAction(as);
		}
		{
			BacksliceContextAction bs = new BacksliceContextAction(this);
			bs.setPopupMenuData(new MenuData(new String[] { "Backward slice" }, null, "operationrun"));
			this.plugin.getTool().addAction(bs);
		}
		{
			SliceContextAction fs = new SliceContextAction(this);
			fs.setPopupMenuData(new MenuData(new String[] { "Forward Slice" }, null, "operationrun"));
			this.plugin.getTool().addAction(fs);
		}
		{
			ExploreBacksliceContextAction bs = new ExploreBacksliceContextAction(this);
			bs.setPopupMenuData(new MenuData(new String[] { "Show backward slice" }, null, "operationrun"));
			this.plugin.getTool().addAction(bs);
		}
		{
			ExploreSliceContextAction fs = new ExploreSliceContextAction(this);
			fs.setPopupMenuData(new MenuData(new String[] { "Show forward Slice" }, null, "operationrun"));
			this.plugin.getTool().addAction(fs);
		}
		{
			AccessorContextAction ac = new AccessorContextAction(this);
			ac.setPopupMenuData(new MenuData(new String[] { "Address accessors" }, null, "operationrun"));
			this.plugin.getTool().addAction(ac);
		}
		{
			TimeWindowContextAction tw = new TimeWindowContextAction(this);
			tw.setPopupMenuData(new MenuData(new String[] { "Time window" }, null, "tick"));
			this.plugin.getTool().addAction(tw);
		}
		{
			FunctionRunAccessesContextAction fra = new FunctionRunAccessesContextAction(this);
			fra.setPopupMenuData(new MenuData(new String[] { "Function run accesses" }, null, "tick"));
			this.plugin.getTool().addAction(fra);
		}
		{
			CallerContextAction cr = new CallerContextAction(this);
			cr.setPopupMenuData(new MenuData(new String[] { "Function call stack" }, null, "tick"));
			this.plugin.getTool().addAction(cr);
		}
		{
			CalleeContextAction ce = new CalleeContextAction(this);
			ce.setPopupMenuData(new MenuData(new String[] { "Function calls made" }, null, "tick"));
			this.plugin.getTool().addAction(ce);
		}
		{
			WhyContextAction a = new WhyContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] { "Why?" }, null, "tick"));
			this.plugin.getTool().addAction(a);
		}
		{
			AllPCRunsContextAction pr = new AllPCRunsContextAction(this);
			pr.setPopupMenuData(new MenuData(new String[] { "PC instances" }, null, "pc"));
			this.plugin.getTool().addAction(pr);
		}

		// Object creation/witness/deletion
		{
			ObjectBirthTypeContextAction ob = new ObjectBirthTypeContextAction(this);
			ob.setPopupMenuData(new MenuData(new String[] { "Create object of known type" }, null, "obj"));
			this.plugin.getTool().addAction(ob);
		}
		{
			ObjectBirthSizeContextAction ob = new ObjectBirthSizeContextAction(this);
			ob.setPopupMenuData(new MenuData(new String[] { "Create object of known size" }, null, "obj"));
			this.plugin.getTool().addAction(ob);
		}
		{
			ObjectBirthSetContextAction a = new ObjectBirthSetContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] { "Birth of selected object" }, null, "obj"));
			this.plugin.getTool().addAction(a);
		}
		{
			ObjectDeathContextAction od = new ObjectDeathContextAction(this);
			od.setPopupMenuData(new MenuData(new String[] { "Terminate selected object" }, null, "obj"));
			this.plugin.getTool().addAction(od);
		}

		/*
		 * { ObjectExistsContextAction oe = new ObjectExistsContextAction(this);
		 * oe.setPopupMenuData(new MenuData(new String[] {"Object exists"}, null,
		 * "obj")); this.plugin.getTool().addAction(oe); } { ObjectDeathContextAction od
		 * = new ObjectDeathContextAction(this); od.setPopupMenuData(new MenuData(new
		 * String[] {"Object death"}, null, "obj"));
		 * this.plugin.getTool().addAction(od); }
		 * 
		 * //
		 */

		// Add menu items to the context menu in the listing as well for navigating to
		// the trace from there
		{
			FindPCInTraceContextAction fp = new FindPCInTraceContextAction(this);
			fp.setPopupMenuData(new MenuData(new String[] { "Find PC in trace" }, null, "trace"));
			this.plugin.getTool().addAction(fp);
		}
	}

	public void doSomething(ActionContext context) {
		System.out.println("qweqweq");
	}

	@Override
	public void buttonPressed(FieldLocation location, Field field, MouseEvent ev) {
		System.out.println(ev.getButton() + " @ " + location.toString());
		this.listingPanel.clearHighlight();
		((TimeListingLayoutModel) this.model).clearHighlight();
		if (ev.getButton() == MouseEvent.BUTTON2) {
			// middle click: if we are on an operation field highlight deps forward and back
			java.awt.Point pt = ev.getPoint();
			FieldLocation floc = new FieldLocation();
			Field f = this.listingPanel.getFieldAt((int) pt.getX(), (int) pt.getY(), floc);
			if (f == null)
				return;
			if (f instanceof SpacetimeOperationField) {
				SpacetimeOperationField sf = (SpacetimeOperationField) f;
				long index = sf.getIndex();
				((TimeListingLayoutModel) this.model).setHighlightOrigin(index);
				String[] params = { Long.toString(index) }; // TODO filters
				try {
					this.listingPanel.clearHighlight();
					// FieldSelection sel = new FieldSelection();
					plugin.runQuery("opdeps", params, this, "highlight"); // see queryCompleted for handling the results 
					// this.listingPanel.setHighlightColor(java.awt.Color.YELLOW);
					// this.listingPanel.setHighlight(sel);
				} catch (Exception e) {
					e.printStackTrace();
					return;
				}
			}
		}
	}

	@Override
	public ActionContext getActionContext(MouseEvent ev) {
		if (ev == null) {
			// something is asking for this without an actual click?
			return new TimeListingActionContext(this, this.listingPanel.getCurrentField(),
					this.listingPanel.getCursorLocation().getIndex());
		}
		java.awt.Point pt = ev.getPoint();
		FieldLocation floc = new FieldLocation();
		Field f = this.listingPanel.getFieldAt((int) pt.getX(), (int) pt.getY(), floc);

		if (f == null) {
			// we clicked but not on any particular field
			return new TimeListingActionContext(this, this.listingPanel.getCurrentField(),
					this.listingPanel.getCursorLocation().getIndex());
		}
		return new TimeListingActionContext(this, f, floc.getIndex());
	}

	@Override
	public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {
		if(location == null) {
			return;
		}
		location.getIndex();
		// set the label to the field's full text
		this.fullFieldFooter.setText(field.getText());

		// Navigate the listing to the pc relevant to what was clicked on
		if (field instanceof SpacetimePCField && this.navigationOutgoingAction.isSelected()) {
			SpacetimePCField sf = (SpacetimePCField) field;
			long pc = sf.getPC();
			Address a = MadnessPlugin.flatApi.toAddr(pc);
			ProgramLocation loc = plugin.getProgramLocation(a, true);
			this.plugin.codeViewer.goTo(loc, true);
		}

		if (field instanceof SpacetimeTickField && this.plugin.calltreeProvider != null) {
			SpacetimeTickField sf = (SpacetimeTickField) field;
			this.plugin.calltreeProvider.tickChanged(sf.getTick());
		}
	}

	@Override
	public JComponent getComponent() {
		// TODO Auto-generated method stub
		return this.mainPanel;
	}

	// ---------------------------------------------------------------
	// Here begin the API entries for other providers to trigger view changes
	public void goToTick(long tick) {
		TimeListingLayoutModel tm = (TimeListingLayoutModel)this.model;
		BigInteger idx = tm.getTickIndex(tick);
		if(idx == null) {
			this.showTimeWindow(tick);
			return;
		}
		this.listingPanel.setCursorPosition(BigInteger.ZERO, 0, 0, 0);
		this.listingPanel.scrollToCursor();
		this.listingPanel.setCursorPosition(idx, 0, 0, 0);
		int visibleIndices = this.listingPanel.getVisibleEndLayout().getIndex().subtract(this.listingPanel.getVisibleStartLayout().getIndex()).intValue();
		this.listingPanel.scrollToCursor();
		for (int i = 0; i < visibleIndices / 2; i++) {
			this.listingPanel.scrollLineDown();
		}
		Long pc = tm.getPCForIndex(idx);
		if(pc != null) {
			Address a = MadnessPlugin.flatApi.toAddr(pc);
			ProgramLocation l = plugin.getProgramLocation(a, true);
			if(l != null) this.plugin.codeViewer.goTo(l, true);
		}
	}
	public void showTimeWindow(long tick) {
		Map<String, Long> params = new HashMap<>();
		params.put(TimeListingView.VIEW_PARAM.TIME_START.name(), tick - TimeListingSettings.TIME_WINDOW_RADIUS);
		params.put(TimeListingView.VIEW_PARAM.TIME_END.name(), tick + TimeListingSettings.TIME_WINDOW_RADIUS);
		TimeListingView v = new TimeListingView(TimeListingView.VIEW_TYPE.TIME_WINDOW_VIEW.name(), params);
		v.lastTick = tick;
		this.newView(v);
	}
	public void showPath(ArrayList<Long> indices) {
		ArrayList<String> indicesStrs = new ArrayList<>();
		for(Long l : indices) {
			indicesStrs.add(l.toString());
		}
		String indicesList = String.join(",", indicesStrs);
		TimeListingView v = new TimeListingView(String.format("let relevant_indices={empty:true}\n"
				+ "let instructions=(for idx in [%s]\n"
				+ "for op in operationruns\n"
				+ "filter op.index == idx\n"
				+ "for ins in instructionruns filter ins.tick == op.tick\n"
				+ "return distinct ins)\n", indicesList), String.format("Path from %d to %d", indices.get(0), indices.get(indices.size()-1)));
		this.newView(v);
	}
	public void showAccessors(long addr) {
		Map<String, Long> params = new HashMap<>();
		params.put(TimeListingView.VIEW_PARAM.ADDR_START.name(), addr);
		params.put(TimeListingView.VIEW_PARAM.ADDR_END.name(), addr);
		this.newView(new TimeListingView(TimeListingView.VIEW_TYPE.ACCESSOR_VIEW.name(), params));
	}

	public void showAccessorsInTime(long addr, long starttick, long endtick) {
		Map<String, Long> params = new HashMap<>();
		params.put(TimeListingView.VIEW_PARAM.ADDR_START.name(), addr);
		params.put(TimeListingView.VIEW_PARAM.ADDR_END.name(), addr);
		params.put(TimeListingView.VIEW_PARAM.TIME_START.name(), starttick);
		params.put(TimeListingView.VIEW_PARAM.TIME_END.name(), endtick);
		this.newView(new TimeListingView(TimeListingView.VIEW_TYPE.OBJ_ACCESSOR_VIEW.name(), params));
	}
	/*
	 * public void showBackwardsSlice(long index) { Map<String, Long> params = new
	 * HashMap<>(); params.put(TimeListingView.VIEW_PARAM.ADDR_START.name(), addr);
	 * params.put(TimeListingView.VIEW_PARAM.ADDR_END.name(), addr);
	 * this.newView(new
	 * TimeListingView(TimeListingView.VIEW_TYPE.ACCESSOR_VIEW.name(), params)); }
	 */

	public void showObjectAccessors(ObjectInfo obj) {
		Map<String, Long> params = new HashMap<>();
		long size = obj.getSize();
		params.put(TimeListingView.VIEW_PARAM.ADDR_START.name(), obj.getBase());
		params.put(TimeListingView.VIEW_PARAM.ADDR_END.name(), obj.getBase() + size);
		params.put(TimeListingView.VIEW_PARAM.TIME_START.name(), obj.getBirth());
		params.put(TimeListingView.VIEW_PARAM.TIME_END.name(), obj.getDeath());
		this.newView(new TimeListingView(TimeListingView.VIEW_TYPE.ADDR_TIME_WINDOW_VIEW.name(), params));
	}

	public void showObjectPhaseAccessors(ObjectInfo obj, ObjectPhase phase) {
		Map<String, Long> params = new HashMap<>();
		long size = obj.getSize();
		params.put(TimeListingView.VIEW_PARAM.ADDR_START.name(), obj.getBase());
		params.put(TimeListingView.VIEW_PARAM.ADDR_END.name(), obj.getBase() + size);
		params.put(TimeListingView.VIEW_PARAM.TIME_START.name(), phase.getStart());
		params.put(TimeListingView.VIEW_PARAM.TIME_END.name(), obj.getPhaseEnd(phase));
		this.newView(new TimeListingView(TimeListingView.VIEW_TYPE.ADDR_TIME_WINDOW_VIEW.name(), params));
	}

	// ---------------------------------------------------------------
	// Here begin the menu item action classes.

	/*
	 * private class TimeListingContextAction extends DockingAction {
	 * 
	 * public TimeListingContextAction(TimeListingProvider provider) {
	 * super("Debug Context", provider.plugin.getName()); }
	 * 
	 * @Override public boolean isEnabledForContext(ActionContext context) { return
	 * true; }
	 * 
	 * @Override public boolean isAddToPopup(ActionContext context) { return true; }
	 * 
	 * @Override public void actionPerformed(ActionContext context) {
	 * System.out.println("DEBUG " + context.toString()); }
	 * 
	 * }
	 */
	private class AccessesContextAction extends DockingAction {
		TimeListingProvider provider;

		public AccessesContextAction(TimeListingProvider provider) {
			super("Show accesses in view", provider.plugin.getName());
			this.provider = provider;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (context instanceof TimeListingActionContext) {
				return true;
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			if (isEnabledForContext(context)) {
				return this.provider.plugin.spaceListingProvider != null
						&& this.provider.plugin.spaceListingProvider.isVisible();
			}
			return false;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			long start, end;
			switch (provider.view.viewType) {
			case ACCESSOR_VIEW:
			case ADDR_WINDOW_VIEW:
				start = provider.view.viewParams.get(TimeListingView.VIEW_PARAM.ADDR_START.name());
				end = provider.view.viewParams.get(TimeListingView.VIEW_PARAM.ADDR_END.name());
				provider.plugin.spaceListingProvider.showAccessesInRange(start, end);
				break;
			case VALUE_VIEW:
			case FORWARDSSLICE_VIEW:
			case BACKWARDSSLICE_VIEW:
			case CALLEE_VIEW:
			case CALLER_VIEW:
				break;
			case TIME_WINDOW_VIEW:
				start = provider.view.viewParams.get(TimeListingView.VIEW_PARAM.TIME_START.name());
				end = provider.view.viewParams.get(TimeListingView.VIEW_PARAM.TIME_END.name());
				provider.plugin.spaceListingProvider.showAccessesInTimeWindow(start, end);
				break;
			default:
				break;

			}
		}

	}

	private class FindPCInTraceContextAction extends DockingAction {

		TimeListingProvider provider;

		public FindPCInTraceContextAction(TimeListingProvider provider) {
			super("Find PC in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_P, InputEvent.ALT_DOWN_MASK));
			this.provider = provider;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (context instanceof ListingActionContext) {
				ListingActionContext lc = (ListingActionContext) context;
				if (isValidContext(lc)) {
					if (lc.getAddress() != null) {
						return true;
					}
				}
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return context instanceof ListingActionContext;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			// TODO Auto-generated method stub
			System.out.println("wooo " + context.toString());
			ListingActionContext lc = (ListingActionContext) context;
			ProgramLocation loc = lc.getLocation();
			Address a = loc.getAddress();
			if (a == null)
				return;
			long offset = a.subtract(loc.getProgram().getImageBase());
			Long abs = provider.plugin.moduleMap.getAbsolute(loc.getProgram().getDomainFile().getPathname(), offset);
			System.out.println("find in trace: " + abs);
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.ADDR_START.name(), abs);
			params.put(TimeListingView.VIEW_PARAM.ADDR_END.name(), abs);
			this.provider.newView(new TimeListingView(TimeListingView.VIEW_TYPE.ADDR_WINDOW_VIEW.name(), params));
		}

	}

	private class AccessorContextAction extends OperationAction {
		public AccessorContextAction(TimeListingProvider provider) {
			super(provider, "Address Accessors in Trace", provider.plugin.getName());
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (super.isEnabledForContext(context)) {
				TimeListingActionContext tc = (TimeListingActionContext) context;
				if (isValidContext(tc)) {
					Field f = tc.getField();
					if (f != null && f instanceof SpacetimeOperationField) {
						SpacetimeOperationField sf = (SpacetimeOperationField) f;
						this.setPopupMenuData(new MenuData(
								new String[] { String.format("Accessors of address 0x%x", sf.getDest()) }, null, "op"));
						return sf.getDest() != null;
					}
				}
			}
			return false;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			System.out.println("accessors " + context.toString());
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			SpacetimeOperationField sf = (SpacetimeOperationField) f;
			Long dest = sf.getDest();
			if (dest == null)
				return;
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.ADDR_START.name(), dest.longValue());
			params.put(TimeListingView.VIEW_PARAM.ADDR_END.name(), dest.longValue());
			this.provider.newView(new TimeListingView(TimeListingView.VIEW_TYPE.ACCESSOR_VIEW.name(), params));
		}

	}

	private class ObjectBirthTypeContextAction extends TickAction {
		public ObjectBirthTypeContextAction(TimeListingProvider provider) {
			super(provider, "Object birth of known type", provider.plugin.getName());
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {

			if (context instanceof TimeListingActionContext) {
				TimeListingActionContext tc = (TimeListingActionContext) context;
				if (isValidContext(tc)) {
					Field f = tc.getField();
					if (f != null && f instanceof SpacetimeOperationField) {
						SpacetimeOperationField sf = (SpacetimeOperationField) f;
						this.setPopupMenuData(new MenuData(
								new String[] { String.format("Create object of known type at 0x%x", sf.getValue()) },
								null, "obj"));
						return true;
					}
				}
			}
			this.setPopupMenuData(new MenuData(new String[] { "Create object of known type" }, null, "obj"));
			return false;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			System.out.println("obj birth " + context.toString());
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			Long starttick = null;
			Long endtick = Long.MAX_VALUE;
			Long base = null;
			DataType ty = null;
			String name = null;
			if (f instanceof SpacetimeOperationField) {
				SpacetimeOperationField sf = (SpacetimeOperationField) f;
				base = sf.getValue().longValue();
			}
			if (f instanceof SpacetimeTickField) {
				SpacetimeTickField sf = (SpacetimeTickField) f;
				starttick = sf.getTick();
			}
			if (base == null) {
				base = provider.plugin.getUserInputLong("base address", "base address");
				if (base == null)
					return;
			}
			if (starttick == null) {
				starttick = provider.plugin.getUserInputLong("birth tick", "birth tick");
				if (starttick == null)
					return;
			}
			ty = provider.plugin.getUserInputDataType();
			if (ty == null)
				return;
			name = provider.plugin.getUserInputString("name", "name");
			if (name == null)
				return;
			long size = ty.getLength();

			ObjectPhase phase = new ObjectPhase(starttick, ty);
			ObjectInfo obj = new ObjectInfo(String.format("%d_%d", starttick, base), name, size, base, starttick,
					endtick, new ObjectPhase[] { phase });

			provider.plugin.madness.setObject(obj);
			provider.plugin.objectManagerProvider.model.reload();
		}

	}

	private class ObjectBirthSizeContextAction extends TickAction {
		public ObjectBirthSizeContextAction(TimeListingProvider provider) {
			super(provider, "Object birth", provider.plugin.getName());
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {

			if (context instanceof TimeListingActionContext) {
				TimeListingActionContext tc = (TimeListingActionContext) context;
				if (isValidContext(tc)) {
					Field f = tc.getField();
					if (f != null && f instanceof SpacetimeOperationField) {
						SpacetimeOperationField sf = (SpacetimeOperationField) f;
						this.setPopupMenuData(new MenuData(
								new String[] { String.format("Create object of known size at 0x%x", sf.getValue()) },
								null, "obj"));
						return true;
					}
				}
			}
			this.setPopupMenuData(new MenuData(new String[] { "Create object of known size" }, null, "obj"));
			return false;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			System.out.println("obj birth " + context.toString());
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			Long starttick = null;
			Long endtick = Long.MAX_VALUE;
			Long base = null;
			DataType ty = null;
			Long sz;
			String name = null;
			if (f instanceof SpacetimeOperationField) {
				SpacetimeOperationField sf = (SpacetimeOperationField) f;
				base = sf.getValue().longValue();
			}
			if (f instanceof SpacetimeTickField) {
				SpacetimeTickField sf = (SpacetimeTickField) f;
				starttick = sf.getTick();
			}
			if (base == null) {
				base = provider.plugin.getUserInputLong("base address", "base address");
				if (base == null)
					return;
			}
			if (starttick == null) {
				starttick = provider.plugin.getUserInputLong("birth tick", "birth tick");
				if (starttick == null)
					return;
			}
			sz = provider.plugin.getUserInputLong("size", "size");
			if (sz == null)
				return;
			String typename = provider.plugin.getUserInputString("typename", "typename");
			if (typename == null)
				return;
			name = provider.plugin.getUserInputString("name", "name");
			if (name == null)
				return;
			ty = new StructureDataType(typename, (int) sz.longValue());
			DataTypeManager mgr = provider.plugin.getDataTypeManager();
			if(mgr == null) {
				return;
			}
			int txid = mgr.startTransaction("adding new type");
			mgr.addDataType(ty, null);
			mgr.endTransaction(txid, true);
			long size = sz.longValue();
			DataType newType = mgr.getDataType("/" + ty.getName());
			ObjectPhase phase = new ObjectPhase(starttick, newType);
			ObjectInfo obj = new ObjectInfo(String.format("%d_%d", starttick, base), name, size, base, starttick,
					endtick, new ObjectPhase[] { phase });

			provider.plugin.madness.setObject(obj);
			provider.plugin.objectManagerProvider.model.reload();

		}

	}

	private class ObjectDeathContextAction extends TickAction {
		public ObjectDeathContextAction(TimeListingProvider provider) {
			super(provider, "Object death", provider.plugin.getName());
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (this.provider.plugin.objectManagerProvider != null) {
				ObjectInfo obj = this.provider.plugin.objectManagerProvider.getSelectedObject();
				if (obj != null) {
					this.setPopupMenuData(
							new MenuData(new String[] { "Terminate object " + obj.getName() }, null, "obj"));
					return true;
				}
			}
			this.setPopupMenuData(new MenuData(new String[] { "Terminate object" }, null, "obj"));
			return false;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			System.out.println("obj death " + context.toString());
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			Long endtick = null;
			if (f instanceof SpacetimeTickField) {
				SpacetimeTickField sf = (SpacetimeTickField) f;
				endtick = sf.getTick();
			} else {
				return;
			}
			List<ObjectInfo> sel = this.provider.plugin.objectManagerProvider.getSelectedObjects();
			if (sel.size() == 1) {
				ObjectInfo o = sel.get(0);
				System.out.println(o.getName() + " dies at " + endtick);
				o.setDeath(endtick);
				provider.plugin.madness.updateObject(o);
			}
			provider.plugin.objectManagerProvider.model.reload();
		}

	}

	private class ObjectBirthSetContextAction extends TickAction {
		public ObjectBirthSetContextAction(TimeListingProvider provider) {
			super(provider, "Object birth set", provider.plugin.getName());
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (this.provider.plugin.objectManagerProvider != null) {
				ObjectInfo obj = this.provider.plugin.objectManagerProvider.getSelectedObject();
				if (obj != null) {
					this.setPopupMenuData(
							new MenuData(new String[] { "Birth object " + obj.getName() }, null, "obj"));
					return true;
				}
			}
			this.setPopupMenuData(new MenuData(new String[] { "Birth selected object" }, null, "obj"));
			return false;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			System.out.println("obj death " + context.toString());
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			Long starttick = null;
			if (f instanceof SpacetimeTickField) {
				SpacetimeTickField sf = (SpacetimeTickField) f;
				starttick = sf.getTick();
			} else {
				return;
			}
			List<ObjectInfo> sel = this.provider.plugin.objectManagerProvider.getSelectedObjects();
			if (sel.size() == 1) {
				ObjectInfo o = sel.get(0);
				System.out.println(o.getName() + " born at " + starttick);
				o.setBirth(starttick);
				provider.plugin.madness.updateObject(o);
			}
			provider.plugin.objectManagerProvider.model.reload();
		}

	}

	// A right-click menu action class should extend the OperationAction
	// class to be available whenever anything with a corresponding operationrun
	// is right-clicked on
	private abstract class OperationAction extends DockingAction {
		TimeListingProvider provider;
		SpacetimeOperationField field;

		public OperationAction(TimeListingProvider provider, String name, String owner) {
			super(name, owner, true);
			this.provider = provider;
			this.field = null;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (context instanceof TimeListingActionContext) {
				TimeListingActionContext tc = (TimeListingActionContext) context;
				if (isValidContext(tc)) {
					Field f = tc.getField();
					if (f != null && f instanceof SpacetimeOperationField) {
						this.field = (SpacetimeOperationField) f;
						return true;
					}
				}
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return context instanceof TimeListingActionContext;
		}
	}

	// A right-click menu action class should extend the PCAction class to be
	// available
	// whenever anything with a corresponding PC is right-clicked on
	private abstract class PCAction extends DockingAction {
		TimeListingProvider provider;
		SpacetimePCField field;

		public PCAction(TimeListingProvider provider, String name, String owner) {
			super(name, owner);
			this.provider = provider;
			this.field = null;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (context instanceof TimeListingActionContext) {
				TimeListingActionContext tc = (TimeListingActionContext) context;
				if (isValidContext(tc)) {
					Field f = tc.getField();
					// We enforce that PC actions are available for fields with a PC
					if (f != null && f instanceof SpacetimePCField) {
						this.field = (SpacetimePCField) f;
						return true;
					}
				}
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return context instanceof TimeListingActionContext;
		}
	}

	// A right-click menu action class should extend the RangeAction class to be
	// available
	// whenever there is a right-click with an active selection
	private abstract class RangeAction extends DockingAction {
		TimeListingProvider provider;

		public RangeAction(TimeListingProvider provider, String name, String owner) {
			super(name, owner);
			this.provider = provider;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (context instanceof TimeListingActionContext) {
				TimeListingActionContext tc = (TimeListingActionContext) context;
				if (isValidContext(tc)) {
					return this.provider.listingPanel.getSelection() != null;
				}
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return context instanceof TimeListingActionContext;
		}
	}

	// A right-click menu action class should extend the TickAction class to be
	// available
	// whenever anything with a corresponding Tick is right-clicked on
	private abstract class TickAction extends DockingAction {
		TimeListingProvider provider;
		SpacetimeTickField field;

		public TickAction(TimeListingProvider provider, String name, String owner) {
			super(name, owner, true);
			this.provider = provider;
			this.field = null;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (context instanceof TimeListingActionContext) {
				TimeListingActionContext tc = (TimeListingActionContext) context;
				if (isValidContext(tc)) {
					Field f = tc.getField();
					// We enforce that tick actions are available for fields with a tick
					if (f != null && f instanceof SpacetimeTickField) {
						this.field = (SpacetimeTickField) f;
						return true;
					}
					f = provider.listingPanel.getCurrentField();
					if (f != null && f instanceof SpacetimeTickField) {
						this.field = (SpacetimeTickField) f;
						return true;
					}
				}
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return context instanceof TimeListingActionContext;
		}
	}

	private class WhyContextAction extends OperationAction {
		public WhyContextAction(TimeListingProvider provider) {
			super(provider, "Why", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_W, 0));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			TimeListingActionContext tc = (TimeListingActionContext) context;
			BigInteger idx = tc.getIndex();
			Long pc = ((TimeListingLayoutModel)(this.provider.model)).getPCForIndex(idx);
			Long tick = ((TimeListingLayoutModel)(this.provider.model)).getTick(idx);
			if(pc == null || tick == null) return false;
			return true;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			TimeListingActionContext tc = (TimeListingActionContext) context;
			BigInteger idx = tc.getIndex();
			Long pc = ((TimeListingLayoutModel)(this.provider.model)).getPCForIndex(idx);
			Long tick = ((TimeListingLayoutModel)(this.provider.model)).getTick(idx);
			Address addr = MadnessPlugin.flatApi.toAddr(pc);
			ProgramLocation a = plugin.getProgramLocation(addr, false);
			a.getProgram().getFunctionManager().getFunctionContaining(a.getAddress());
			try {
				CodeBlock blocks[] = (new BasicBlockModel(a.getProgram())).getCodeBlocksContaining(a.getAddress(), null);
				if (blocks.length == 0) {
					Msg.showError(this, null, "Madness Error", "no blocks containing address" + addr);
					return;
				}
				
				String[] params = { Long.toString(tick), Long.toString(blocks[0].getFirstStartAddress().getOffset()), a.getProgram().getDomainFile().getPathname(), Long.toString(a.getProgram().getImageBase().getOffset())};
				plugin.runQuery("why", params, this.provider, "why");
			} catch (Exception exc) {
				exc.printStackTrace();
			}
		}
	}

	private class ExploreBacksliceContextAction extends OperationAction {
		public ExploreBacksliceContextAction(TimeListingProvider provider) {
			super(provider, "Show Backward Slice in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_P, 0));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			boolean ans = super.isEnabledForContext(context);
			if (ans) {
				this.setPopupMenuData(
						new MenuData(new String[] { "Show backward slice " + this.field.getDescription() }, null, "op"));
			} else {
				this.setPopupMenuData(new MenuData(new String[] { "Show backward slice" }, null, "op"));
			}
			return ans;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			SpacetimeOperationField sf = (SpacetimeOperationField) f;
			long index = sf.getIndex();
			System.out.println("show backslice " + f.toString());
			SliceListingProvider s = new SliceListingProvider(this.provider.plugin, index, 50, false);
			s.addToTool();
			s.setVisible(true);
		}
	}

	private class ExploreSliceContextAction extends OperationAction {
		public ExploreSliceContextAction(TimeListingProvider provider) {
			super(provider, "Show Forward Slice in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_N, 0));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			boolean ans = super.isEnabledForContext(context);
			if (ans) {
				this.setPopupMenuData(
						new MenuData(new String[] { "Show forward slice " + this.field.getDescription() }, null, "op"));
			} else {
				this.setPopupMenuData(new MenuData(new String[] { "Show forward slice" }, null, "op"));
			}
			return ans;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			SpacetimeOperationField sf = (SpacetimeOperationField) f;
			long index = sf.getIndex();
			System.out.println("show backslice " + f.toString());
			SliceListingProvider s = new SliceListingProvider(this.provider.plugin, index, 50, true);
			s.addToTool();
			s.setVisible(true);
		}
	}

	private class BacksliceContextAction extends OperationAction {
		public BacksliceContextAction(TimeListingProvider provider) {
			super(provider, "Backward Slice in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_B, 0));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			boolean ans = super.isEnabledForContext(context);
			if (ans) {
				this.setPopupMenuData(
						new MenuData(new String[] { "Backward slice " + this.field.getDescription() }, null, "op"));
			} else {
				this.setPopupMenuData(new MenuData(new String[] { "Backward slice" }, null, "op"));
			}
			return ans;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			SpacetimeOperationField sf = (SpacetimeOperationField) f;
			long index = sf.getIndex();
			System.out.println("backslice " + f.toString());
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.INDEX.name(), index);
			params.put(TimeListingView.VIEW_PARAM.DEPTH.name(),
					(long) (int) this.provider.plugin.sliceDepthSetting.getValue());
			this.provider.newView(new TimeListingView(TimeListingView.VIEW_TYPE.BACKWARDSSLICE_VIEW.name(), params));
		}
	}

	private class SliceContextAction extends OperationAction {
		public SliceContextAction(TimeListingProvider provider) {
			super(provider, "Forward Slice in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_F, 0));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			boolean ans = super.isEnabledForContext(context);
			if (ans) {
				this.setPopupMenuData(
						new MenuData(new String[] { "Forward slice " + this.field.getDescription() }, null, "op"));
			} else {
				this.setPopupMenuData(new MenuData(new String[] { "Forward slice" }, null, "op"));
			}
			return ans;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			SpacetimeOperationField sf = (SpacetimeOperationField) f;
			long index = sf.getIndex();
			System.out.println("slice " + f.toString());
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.INDEX.name(), index);
			params.put(TimeListingView.VIEW_PARAM.DEPTH.name(),
					(long) (int) this.provider.plugin.sliceDepthSetting.getValue());
			this.provider.newView(new TimeListingView(TimeListingView.VIEW_TYPE.FORWARDSSLICE_VIEW.name(), params));
		}
	}

	private class AllPCRunsContextAction extends PCAction {
		public AllPCRunsContextAction(TimeListingProvider provider) {
			super(provider, "All PC Runs in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_P, 0));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			SpacetimePCField sf = (SpacetimePCField) f;
			long pc = sf.getPC();
			System.out.println("goto " + f.toString());
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.ADDR_START.name(), pc);
			params.put(TimeListingView.VIEW_PARAM.ADDR_END.name(), pc);
			this.provider.newView(new TimeListingView(TimeListingView.VIEW_TYPE.ADDR_WINDOW_VIEW.name(), params));
		}
	}

	private class TimeWindowContextAction extends TickAction {
		public TimeWindowContextAction(TimeListingProvider provider) {
			super(provider, "Time Window in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, 0));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			boolean ans = super.isEnabledForContext(context);
			if (ans) {
				this.setPopupMenuData(
						new MenuData(new String[] { String.format("Time window around tick %d", this.field.getTick()) },
								null, "tick"));
			} else {
				this.setPopupMenuData(new MenuData(new String[] { "Time window" }, null, "tick"));
			}
			return ans;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			if (f == null) {
				f = provider.listingPanel.getCurrentField();
			}
			if (f == null)
				return;
			SpacetimeTickField sf = (SpacetimeTickField) f;
			long tick = sf.getTick();
			System.out.println("TIMEWINDOW " + f.toString());
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.TIME_START.name(), tick - TimeListingSettings.TIME_WINDOW_RADIUS);
			params.put(TimeListingView.VIEW_PARAM.TIME_END.name(), tick + TimeListingSettings.TIME_WINDOW_RADIUS);
			TimeListingView v = new TimeListingView(TimeListingView.VIEW_TYPE.TIME_WINDOW_VIEW.name(), params);
			v.lastTick = tick;
			this.provider.newView(v);
		}
	}

	private class FunctionRunAccessesContextAction extends TickAction {
		public FunctionRunAccessesContextAction(TimeListingProvider provider) {
			super(provider, "Memory accessed during current function run", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_M, 0));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			SpacetimeTickField sf = (SpacetimeTickField) f;
			long tick = sf.getTick();
			System.out.println("accesses during " + f.toString());
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.TIME_START.name(), tick);
			params.put(TimeListingView.VIEW_PARAM.DEPTH.name(), 10L);
			this.provider.plugin.spaceListingProvider
					.newView(new SpaceListingView(SpaceListingView.VIEW_TYPE.FUNCTION_RUN_VIEW.name(), params));
		}
	}

	private class CalleeContextAction extends TickAction {
		public CalleeContextAction(TimeListingProvider provider) {
			super(provider, "Function Callees in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_C, 0));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			SpacetimeTickField sf = (SpacetimeTickField) f;
			long tick = sf.getTick();
			System.out.println("callee " + f.toString());
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.TIME_START.name(), tick);
			params.put(TimeListingView.VIEW_PARAM.DEPTH.name(), 10L);
			this.provider.newView(new TimeListingView(TimeListingView.VIEW_TYPE.CALLEE_VIEW.name(), params));
		}
	}

	private class CallerContextAction extends TickAction {
		public CallerContextAction(TimeListingProvider provider) {
			super(provider, "Function Callers in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_K, 0));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			TimeListingActionContext tc = (TimeListingActionContext) context;
			Field f = tc.getField();
			SpacetimeTickField sf = (SpacetimeTickField) f;
			long tick = sf.getTick();
			System.out.println("caller " + f.toString());
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.TIME_START.name(), tick);
			params.put(TimeListingView.VIEW_PARAM.DEPTH.name(), 10L);
			this.provider.newView(new TimeListingView(TimeListingView.VIEW_TYPE.CALLER_VIEW.name(), params));
		}
	}

	@Override
	public boolean isShowing() {
		return false;
	}

	@Override
	public void closeHover() {
	}

	@Override
	public void mouseHovered(FieldLocation fieldLocation, Field field, Rectangle fieldBounds, MouseEvent event) {
		if (field == null)
			return;
		MadnessPlugin.LOG.debug(field.toString());
	}

	@Override
	public void scroll(int amount) {
	}

	@Override
	public void selectionChanged(FieldSelection selection, EventTrigger trigger) {
		BigInteger currentIndex = this.listingPanel.getCursorLocation().getIndex();
		if(currentIndex == null) {
			return;
		}
		Long currentPc = ((TimeListingLayoutModel) this.model).getPCForIndex(currentIndex);
		ProgramLocation currentLoc = this.plugin.getProgramLocation(MadnessPlugin.flatApi.toAddr(currentPc), true);
		Program currentProgram = currentLoc.getProgram();
		
		AddressSet sel = new AddressSet();
		for (FieldRange fr : selection) {
			BigInteger start = fr.getStart().getIndex();
			BigInteger end = fr.getEnd().getIndex();
			// ensure start <= end
			if (start.compareTo(end) > 0) {
				BigInteger tmp = start;
				start = end;
				end = tmp;
			}
			for (BigInteger idx = start; idx.compareTo(end) <= 0; idx = idx.add(BigInteger.ONE)) {
				Long pc = ((TimeListingLayoutModel) this.model).getPCForIndex(idx);
				if (pc == null)
					continue;
				Address a = MadnessPlugin.flatApi.toAddr(pc);
				ProgramLocation loc = this.plugin.getProgramLocation(a, false);
				if(loc != null && loc.getProgram() == currentProgram) {
					sel.add(loc.getAddress());
				}
			}
		}
		if(sel.getNumAddresses() == 0) return;
		ProgramSelection ps = new ProgramSelection(sel);
		this.plugin.codeViewer.getNavigatable().setSelection(ps);
	}

	@Override
	public Color getBackgroundColor(BigInteger index) {
		if (this.listingPanel.getCursorLocation().getIndex().equals(index)) {
			return TimeListingSettings.CURSOR_HIGHLIGHT_COLOR;
		}
		return TimeListingSettings.BACKGROUND_COLOR;
	}

	@Override
	public Color getDefaultBackgroundColor() {
		return TimeListingSettings.BACKGROUND_COLOR;
	}

	@Override
	public void setDefaultBackgroundColor(Color c) {
		return;
	}

	@Override
	public void queryCompleted(List<JSONObject> results, String tag) {
		if(tag.equals("gotoReturn")) {
			if(results.size() > 0) {
				JSONObject r = results.get(0);
				Long t = r.getLong("endtick");
				this.goToTick(t);
			}			
		} else if(tag.equals("gotoCallsite")) {
			if(results.size() > 0) {
				JSONObject r = results.get(0);
				Long t = r.getLong("calltick");
				this.goToTick(t);
			}
		} else if(tag.equals("highlight")) {
			TimeListingProvider self = this;
			Swing.runLater(new Runnable(){
				public void run() {
					for (int i = 0; i < results.size(); i++) {
						JSONObject obj = results.get(i);
						// long highlightTick = obj.getLong("tick");
						long highlightIndex = obj.getLong("index");
						long highlightDist = obj.getLong("dist");
						((TimeListingLayoutModel) self.model).addHighlight(highlightIndex, highlightDist);
					}
					self.listingPanel.repaint();	
				}
			});
		} else if(tag.equals("why")) {
			for (var obj : results) {
				long whytick = obj.getLong("tick");
				this.goToTick(whytick);
				break;
			}
		} else {
			MadnessPlugin.LOG.error("unknown query result: " + tag);
		}
		
	}
}

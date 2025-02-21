package tracemadness.spacelisting;

import java.awt.BorderLayout;
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

//import ghidra.app.util.bin.format.dwarf4.funcfixup.ThisCallingConventionDWARFFunctionFixup;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.util.ProgramSelection;
import resources.Icons;
import tracemadness.MadnessPlugin;
import tracemadness.listingfield.SpacetimeAddrField;
import tracemadness.listingfield.SpacetimeOperationField;
import tracemadness.listingfield.SpacetimeTickField;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.objectdata.ObjectPhase;
import tracemadness.timelisting.TimeListingSettings;
import tracemadness.timelisting.TimeListingView;
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
import docking.widgets.fieldpanel.listener.FieldSelectionListener;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.indexedscrollpane.IndexedScrollPane;

public class SpaceListingProvider 
	extends ComponentProvider 
	implements FieldLocationListener, 
		FieldSelectionListener,
		ActionContextProvider, 
		HoverProvider {

	private JComponent mainPanel;
	private IndexedScrollPane scroller; // The scroll pane containing the listing panel
	private FieldPanel listingPanel; // the panel for the main instruction listing
	private JLabel fullFieldFooter; // the footer for displaying the full versions of clipped text
	private JLabel currentViewFooter; // the footer for displaying the full versions of clipped text
	private LayoutModel model;
	private MadnessPlugin plugin;
	private SpaceListingView view;
	private Font font;
	private FontMetrics fontMetrics;

	private ToggleDockingAction navigationOutgoingAction;
	private ToggleDockingAction navigationIncomingAction;
	private List<SpaceListingView> history;
	private int historyCursor;
	
	public SpaceListingProvider(MadnessPlugin plugin, String name) {
		// TODO what is the "owner" third parameter here supposed to be?
		super(plugin.getTool(), name, name);
		this.plugin = plugin;
		this.mainPanel = new JPanel();
		font = new Font("Monospaced", Font.PLAIN, 14);
		this.mainPanel.setFont(font);
		this.fontMetrics = this.mainPanel.getFontMetrics(font);
		
		// init the history
		this.view = new SpaceListingView();
		this.history = new ArrayList<>();
		this.historyAdd(this.view);
		
		this.model = new SpaceListingLayoutModel(this.plugin, this, this.view, this.fontMetrics);
		this.listingPanel = new FieldPanel(this.model, "Time listing");
		this.listingPanel.setFont(font);
		
		// Add the click listeners
		setupMouseListeners();
		
		// Add the context menu items and ensure that right clicks in this provider's component happen in the SpaceListingActionContext context
		plugin.getTool().registerDefaultContextProvider(SpaceListingActionContext.class, this);
		createContextActions();
		
		// Add the docking actions
		createDockingActions();
		
		// Set the hover handler
		this.listingPanel.setHoverProvider(this);
		
		// Make the GUI
		buildSpaceListingPanel();
	}
	
	public void historyAdd(SpaceListingView v) {
		for (int i = this.historyCursor + 1; i < this.history.size();) {
			this.history.remove(i);
		}
		if(this.listingPanel != null) {
			v.lastAddress = ((SpaceListingLayoutModel) this.model).getAddress(this.listingPanel.getCursorLocation().getIndex());
		}
		this.history.add(v);
		this.historyCursor++;
	}
	public SpaceListingView getCurrentHistory() {
		if (this.history.size() == 0)
			return null;
		return this.history.get(this.historyCursor);
	}
	public SpaceListingView historyBack() {
		if (this.history.size() == 0)
			return null;
		if(this.historyCursor == 0)
			return null;
		this.historyCursor = Math.max(this.historyCursor - 1, 0);
		return this.history.get(this.historyCursor);
	}
	public SpaceListingView historyForward() {
		if (this.history.size() == 0)
			return null;
		if(this.historyCursor == this.history.size()-1)
			return null;
		this.historyCursor = Math.min(this.historyCursor + 1, this.history.size() - 1);
		return this.history.get(this.historyCursor);
	}
	
	public SpaceListingView getView() {
		return this.view;
	}
	
	// makes a new view and sets it (adds to the history)
	public void newView(SpaceListingView v) {
		this.historyAdd(v);
		this.setView(v);
	}
	
	// simply sets the view (does not add to history)
	public void setView(SpaceListingView view) {
		this.view = view;
		currentViewFooter.setText("Now viewing: " + this.view.toString());
		this.model = new SpaceListingLayoutModel(this.plugin, this, view, this.fontMetrics);
	}
	
	public void refresh() {
		this.listingPanel.setLayoutModel(this.model);
		this.scroller.indexModelChanged();
		if(this.view.lastAddress != null && this.listingPanel != null) {
			BigInteger idx = ((SpaceListingLayoutModel)this.model).getAddressIndex(this.view.lastAddress);
			if(idx != null)	this.listingPanel.setCursorPosition(idx, 0, 0, 0);
			var endLayout = this.listingPanel.getVisibleEndLayout();
			if(endLayout == null) {
				return;
			}
			int visibleIndices = endLayout.getIndex().subtract(this.listingPanel.getVisibleStartLayout().getIndex()).intValue();
			this.listingPanel.scrollToCursor();
			for(int i = 0; i < visibleIndices/2; i++) {
				this.listingPanel.scrollLineDown();
			}
		}
		
	}
	
	public void dispose() {
		plugin.getTool().unregisterDefaultContextProvider(SpaceListingActionContext.class, this);
	}
	
	// Customize GUI
	private void buildSpaceListingPanel() {
		this.mainPanel.setLayout(new BorderLayout());
		this.scroller = new IndexedScrollPane(this.listingPanel);
		//scroller.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		//scroller.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
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
		this.listingPanel.addFieldSelectionListener(this);
	}

	private void createDockingActions() {

		SpaceListingProvider self = this;
		// Go back in history
		DockingAction undoHistoryAction = new DockingAction("Back", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				SpaceListingView v = self.historyBack();
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
				SpaceListingView v = self.historyForward();
				if (v != null)
					self.setView(v);
			}
		};
		redoHistoryAction.setToolBarData(new ToolBarData(Icons.RIGHT_ICON, null));
		redoHistoryAction.setEnabled(true);
		this.addLocalAction(redoHistoryAction);

		// Toggling outgoing anchor updates
		navigationOutgoingAction = new ToggleDockingAction("Toggle Outgoing Synchanges", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				// No code needed here - it automatically updates
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
				// No code needed here - it automatically updates
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
		{
		AccessorContextAction ar = new AccessorContextAction(this);
		ar.setPopupMenuData(new MenuData(new String[] {"All address accessors"}, null, "addr"));
		this.plugin.getTool().addAction(ar);
		}
		{
		ObjectAccessorContextAction oa = new ObjectAccessorContextAction(this);
		oa.setPopupMenuData(new MenuData(new String[] {"All object address accessors"}, null, "addr"));
		this.plugin.getTool().addAction(oa);
		}
		{
		BackSliceContextAction bs = new BackSliceContextAction(this);
		bs.setPopupMenuData(new MenuData(new String[] {"Backward slice"}, null, "operationrun"));
		this.plugin.getTool().addAction(bs);
		}
		{
		SliceContextAction fs = new SliceContextAction(this);
		fs.setPopupMenuData(new MenuData(new String[] {"Forward Slice"}, null, "operationrun"));
		this.plugin.getTool().addAction(fs);
		}
		{
		GoToTimeWindowContextAction tw = new GoToTimeWindowContextAction(this);
		tw.setPopupMenuData(new MenuData(new String[] {"Time window"}, null, "operationrun"));
		this.plugin.getTool().addAction(tw);
		}
	}
	
	@Override
	public ActionContext getActionContext(MouseEvent ev) {
		if(ev == null) {
			// something is asking for this without an actual click?
			return new SpaceListingActionContext(this, this.listingPanel.getCurrentField());			
		}
		java.awt.Point pt = ev.getPoint();
		FieldLocation floc = new FieldLocation();
		Field f = this.listingPanel.getFieldAt((int)pt.getX(), (int)pt.getY(), floc);
		if(f == null) {
			// we clicked but not on any particular field
			return new SpaceListingActionContext(this, this.listingPanel.getCurrentField());
		}
		return new SpaceListingActionContext(this, f);
	}
	
	@Override
	public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {
	
		System.out.println("location -> " + location.toString() + " in " + field.toString());
		location.getIndex();
		// set the label to the field's full text
		this.fullFieldFooter.setText(field.getText());
	}
	
	@Override
	public JComponent getComponent() {
		// TODO Auto-generated method stub
		return this.mainPanel;
	}
	//---------------------------------------------------------------
	// Here begin the API functions to call the  
	public void showAccessesInRange(long start, long end) {
		HashMap<String, Long> params = new HashMap<>();
		params.put(SpaceListingView.VIEW_PARAM.ADDR_START.name(), start);
		params.put(SpaceListingView.VIEW_PARAM.ADDR_END.name(), end);
		this.newView(new SpaceListingView(SpaceListingView.VIEW_TYPE.ADDR_WINDOW_VIEW.name(), params));
	}
	public void showObjectAccesses(ObjectInfo obj) {
		HashMap<String, Long> params = new HashMap<>();
		long size = obj.getSize();
		params.put(SpaceListingView.VIEW_PARAM.ADDR_START.name(), obj.getBase());
		params.put(SpaceListingView.VIEW_PARAM.ADDR_END.name(), obj.getBase()+size);
		params.put(SpaceListingView.VIEW_PARAM.TIME_START.name(), obj.getBirth());
		params.put(SpaceListingView.VIEW_PARAM.TIME_END.name(), obj.getDeath());
		this.newView(new SpaceListingView(SpaceListingView.VIEW_TYPE.ADDR_TIME_WINDOW_VIEW.name(), params));
	}
	public void showObjectPhaseAccesses(ObjectInfo obj, ObjectPhase phase) {
		HashMap<String, Long> params = new HashMap<>();
		long size = obj.getSize();
		params.put(SpaceListingView.VIEW_PARAM.ADDR_START.name(), obj.getBase());
		params.put(SpaceListingView.VIEW_PARAM.ADDR_END.name(), obj.getBase()+size);
		params.put(SpaceListingView.VIEW_PARAM.TIME_START.name(), phase.getStart());
		params.put(SpaceListingView.VIEW_PARAM.TIME_END.name(), obj.getPhaseEnd(phase));
		this.newView(new SpaceListingView(SpaceListingView.VIEW_TYPE.ADDR_TIME_WINDOW_VIEW.name(), params));
	}
	public void showAccessesInTimeWindow(long start, long end) {
		HashMap<String, Long> params = new HashMap<>();
		params.put(SpaceListingView.VIEW_PARAM.TIME_START.name(), start);
		params.put(SpaceListingView.VIEW_PARAM.TIME_END.name(), end);
		this.newView(new SpaceListingView(SpaceListingView.VIEW_TYPE.TIME_WINDOW_VIEW.name(), params));
	}
	
	//---------------------------------------------------------------
	// Here begin the menu item action classes. 

	private class AccessorContextAction extends AddrAction {
		public AccessorContextAction(SpaceListingProvider provider) {
			super(provider, "All Accessors", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_A, InputEvent.ALT_DOWN_MASK | InputEvent.CTRL_DOWN_MASK));
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(super.isEnabledForContext(context)) {
				SpaceListingActionContext tc = (SpaceListingActionContext) context; 
				if(isValidContext(tc)) {
					Field f = tc.getField();
					if(f != null && f instanceof SpacetimeAddrField) {
						return true;
					}
				}
			}
			return false;
		}
		
		@Override
		public void actionPerformed(ActionContext context) {
			System.out.println("accessors " + context.toString());
			SpaceListingActionContext tc = (SpaceListingActionContext) context; 
			Field f = tc.getField();
			SpacetimeAddrField sf = (SpacetimeAddrField) f;
			long addr = sf.getAddr();
			provider.plugin.timeListingProvider.showAccessors(addr);
		}
		
	}

	private class ObjectAccessorContextAction extends AddrAction {
		public ObjectAccessorContextAction(SpaceListingProvider provider) {
			super(provider, "All Object Accessors", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_A, InputEvent.ALT_DOWN_MASK));
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(super.isEnabledForContext(context)) {
				SpaceListingActionContext tc = (SpaceListingActionContext) context; 
				if(isValidContext(tc)) {
					Field f = tc.getField();
					if(f != null && f instanceof SpacetimeAddrField) {
						if(this.provider.view.viewType.name().equals(SpaceListingView.VIEW_TYPE.ADDR_TIME_WINDOW_VIEW.name())) {
							return true;							
						}
					}
				}
			}
			return false;
		}
		
		@Override
		public void actionPerformed(ActionContext context) {
			if(!this.provider.view.viewType.name().equals(SpaceListingView.VIEW_TYPE.ADDR_TIME_WINDOW_VIEW.name())) {
				return;
			}
			long starttick = this.provider.view.getViewParam(SpaceListingView.VIEW_PARAM.TIME_START.name());
			long endtick = this.provider.view.getViewParam(SpaceListingView.VIEW_PARAM.TIME_END.name());
			System.out.println("accessors " + context.toString());
			SpaceListingActionContext tc = (SpaceListingActionContext) context; 
			Field f = tc.getField();
			SpacetimeAddrField sf = (SpacetimeAddrField) f;
			long addr = sf.getAddr();
			provider.plugin.timeListingProvider.showAccessorsInTime(addr, starttick, endtick);
		}
		
	}

	// A right-click menu action class should extend the OperationAction 
	// class to be available whenever anything with a corresponding operationrun 
	// is right-clicked on  
	private abstract class OperationAction extends DockingAction {
		SpaceListingProvider provider;
		public OperationAction(SpaceListingProvider provider, String name, String owner) {
			super(name, owner, true);
			this.provider = provider;
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(context instanceof SpaceListingActionContext) {
				SpaceListingActionContext tc = (SpaceListingActionContext) context; 
				if(isValidContext(tc)) {
					Field f = tc.getField();
					if(f != null && f instanceof SpacetimeOperationField) {
						return true;
					}
				}
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return context instanceof SpaceListingActionContext;
		}
	}

	private class GoToTimeWindowContextAction extends OperationAction {
		public GoToTimeWindowContextAction(SpaceListingProvider provider) {
			super(provider, "Go To Memory Operation in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, 0));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			SpaceListingActionContext tc = (SpaceListingActionContext) context; 
			Field f = tc.getField();
			if(!(f instanceof SpacetimeTickField)) {
				return;
			}
			SpacetimeTickField sf = (SpacetimeTickField) f;
			long tick = sf.getTick();
			System.out.println("slice " + f.toString());
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.TIME_START.name(), tick-TimeListingSettings.TIME_WINDOW_RADIUS);
			params.put(TimeListingView.VIEW_PARAM.TIME_END.name(), tick+TimeListingSettings.TIME_WINDOW_RADIUS);
			TimeListingView v = new TimeListingView(TimeListingView.VIEW_TYPE.TIME_WINDOW_VIEW.name(), params);
			v.lastTick = tick;
			this.provider.plugin.timeListingProvider.newView(v);
		}
	}
	private class SliceContextAction extends OperationAction {
		public SliceContextAction(SpaceListingProvider provider) {
			super(provider, "Forward Slice Memory Operation in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_F, 0));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			SpaceListingActionContext tc = (SpaceListingActionContext) context; 
			Field f = tc.getField();
			SpacetimeOperationField sf = (SpacetimeOperationField) f;
			long index = sf.getIndex();
			System.out.println("slice " + f.toString());
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.INDEX.name(), index);
			params.put(TimeListingView.VIEW_PARAM.DEPTH.name(), (long)(int)this.provider.plugin.sliceDepthSetting.getValue());
			this.provider.plugin.timeListingProvider.newView(new TimeListingView(TimeListingView.VIEW_TYPE.FORWARDSSLICE_VIEW.name(), params));
		}
	}
	private class BackSliceContextAction extends OperationAction {
		public BackSliceContextAction(SpaceListingProvider provider) {
			super(provider, "Backward Slice Memory Operation in Trace", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_B, 0));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			SpaceListingActionContext tc = (SpaceListingActionContext) context; 
			Field f = tc.getField();
			SpacetimeOperationField sf = (SpacetimeOperationField) f;
			long index = sf.getIndex();
			System.out.println("backslice " + f.toString());
			Map<String, Long> params = new HashMap<>();
			params.put(TimeListingView.VIEW_PARAM.INDEX.name(), index);
			params.put(TimeListingView.VIEW_PARAM.DEPTH.name(), (long)(int)this.provider.plugin.sliceDepthSetting.getValue());
			this.provider.plugin.timeListingProvider.newView(new TimeListingView(TimeListingView.VIEW_TYPE.BACKWARDSSLICE_VIEW.name(), params));
		}
	}

	
	// A right-click menu action class should extend the PCAction class to be available 
	// whenever anything with a corresponding PC is right-clicked on  
	private abstract class AddrAction extends DockingAction {
		SpaceListingProvider provider;
		public AddrAction(SpaceListingProvider provider, String name, String owner) {
			super(name, owner);
			this.provider = provider;
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(context instanceof SpaceListingActionContext) {
				SpaceListingActionContext tc = (SpaceListingActionContext) context; 
				if(isValidContext(tc)) {
					Field f = tc.getField();
					// We enforce that PC actions are available for fields with a PC
					if(f != null && f instanceof SpacetimeAddrField) {
						return true;
					}
				}
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return context instanceof SpaceListingActionContext;
		}
	}

	// A right-click menu action class should extend the RangeAction class to be available 
	// whenever there is a right-click with an active selection  
	private abstract class RangeAction extends DockingAction {
		SpaceListingProvider provider;
		public RangeAction(SpaceListingProvider provider, String name, String owner) {
			super(name, owner);
			this.provider = provider;
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(context instanceof SpaceListingActionContext) {
				SpaceListingActionContext tc = (SpaceListingActionContext) context; 
				if(isValidContext(tc)) {
					return this.provider.listingPanel.getSelection() != null;
				}
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return context instanceof SpaceListingActionContext;
		}
	}
	
	@Override
	public boolean isShowing() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void closeHover() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void mouseHovered(FieldLocation fieldLocation, Field field, Rectangle fieldBounds, MouseEvent event) {
		// TODO Auto-generated method stub
		if(field == null) return;
		System.out.println(field);
	}

	@Override
	public void scroll(int amount) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void selectionChanged(FieldSelection selection, EventTrigger trigger) {
		AddressSet sel = new AddressSet();
		for(FieldRange fr : selection) {
			BigInteger start = fr.getStart().getIndex();
			BigInteger end = fr.getEnd().getIndex();
			// ensure start <= end
			if(start.compareTo(end) > 0) {
				BigInteger tmp = start;
				start = end;
				end = tmp;
			} 
			for(BigInteger idx = start; idx.compareTo(end) <= 0; idx = idx.add(BigInteger.ONE)) {
				Long pc = ((SpaceListingLayoutModel)this.model).getPCForIndex(idx);
				if(pc == null) continue;
				Address a = MadnessPlugin.flatApi.toAddr(pc);
				sel.add(a);
			}
		}
		ProgramSelection ps = new ProgramSelection(sel);
		this.plugin.codeViewer.getNavigatable().setSelection(ps);
	}
}

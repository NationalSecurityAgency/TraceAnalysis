package tracemadness.memorylisting;

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
import tracemadness.memindex.MemorySearchResult;
import tracemadness.memsearchlisting.MemSearchListingProvider;
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
import generic.theme.GIcon;

public class MemoryListingProvider 
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
	private MemoryListingView view;
	private Font font;
	private FontMetrics fontMetrics;

	private ToggleDockingAction navigationOutgoingAction;
	private ToggleDockingAction navigationIncomingAction;
	private List<MemoryListingView> history;
	private int historyCursor;
	
	public MemoryListingProvider(MadnessPlugin plugin, String name) {
		// TODO what is the "owner" third parameter here supposed to be?
		super(plugin.getTool(), name, name);
		this.plugin = plugin;
		this.mainPanel = new JPanel();
		font = new Font("Monospaced", Font.PLAIN, 14);
		this.mainPanel.setFont(font);
		this.fontMetrics = this.mainPanel.getFontMetrics(font);
		
		// init the history
		this.view = new MemoryListingView();
		this.history = new ArrayList<>();
		this.historyAdd(this.view);

		this.model = new MemoryListingLayoutModel(this.plugin, this, this.view, this.fontMetrics);
		this.listingPanel = new FieldPanel(this.model, "Time listing");
		this.listingPanel.setFont(font);
		
		// Add the click listeners
		setupMouseListeners();
		
		// Add the context menu items and ensure that right clicks in this provider's component happen in the SpaceListingActionContext context
		plugin.getTool().registerDefaultContextProvider(MemoryListingActionContext.class, this);
		createContextActions();
		
		// Add the docking actions
		createDockingActions();
		
		// Set the hover handler
		this.listingPanel.setHoverProvider(this);
		
		// Make the GUI
		buildSpaceListingPanel();
		this.refresh();
	}
	
	public void historyAdd(MemoryListingView v) {
		for (int i = this.historyCursor + 1; i < this.history.size();) {
			this.history.remove(i);
		}
		if(this.listingPanel != null) {
			v.lastAddress = ((MemoryListingLayoutModel) this.model).getAddress(this.listingPanel.getCursorLocation().getIndex());
		}
		this.history.add(v);
		this.historyCursor++;
	}
	public MemoryListingView getCurrentHistory() {
		if (this.history.size() == 0)
			return null;
		return this.history.get(this.historyCursor);
	}
	public MemoryListingView historyBack() {
		if (this.history.size() == 0)
			return null;
		if(this.historyCursor == 0)
			return null;
		this.historyCursor = Math.max(this.historyCursor - 1, 0);
		return this.history.get(this.historyCursor);
	}
	public MemoryListingView historyForward() {
		if (this.history.size() == 0)
			return null;
		if(this.historyCursor == this.history.size()-1)
			return null;
		this.historyCursor = Math.min(this.historyCursor + 1, this.history.size() - 1);
		return this.history.get(this.historyCursor);
	}
	
	public MemoryListingView getView() {
		return this.view;
	}
	
	// makes a new view and sets it (adds to the history)
	public void newView(MemoryListingView v) {
		this.historyAdd(v);
		this.setView(v);
	}
	
	// simply sets the view (does not add to history)
	public void setView(MemoryListingView view) {
		this.view = view;
		currentViewFooter.setText("Now viewing: " + this.view.toString());
		this.model = new MemoryListingLayoutModel(this.plugin, this, view, this.fontMetrics);
		this.refresh();
	}
	
	public void refresh() {
		this.listingPanel.setLayoutModel(this.model);
		this.scroller.indexModelChanged();
		if(this.view.lastAddress != null && this.listingPanel != null) {
			BigInteger idx = ((MemoryListingLayoutModel)this.model).getAddressIndex(this.view.lastAddress);
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
		plugin.getTool().unregisterDefaultContextProvider(MemoryListingActionContext.class, this);
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

		MemoryListingProvider self = this;
		// Go back in history
		DockingAction undoHistoryAction = new DockingAction("Back", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				MemoryListingView v = self.historyBack();
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
				MemoryListingView v = self.historyForward();
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

		// Go to tick
		DockingAction gotoAction = new DockingAction("Go To Tick", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				Long tick = self.plugin.getUserInputLong("tick", "tick");
				Long addr = self.plugin.getUserInputLong("addr", "addr");
				Long len = self.plugin.getUserInputLong("len", "len");
				if (tick != null && addr != null && len != null) {
					self.showMemory(addr, len, tick);
				}
			}
		};
		gotoAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.datatypes.filter.pointers.off"), null));
		gotoAction.setEnabled(true);
		this.addLocalAction(gotoAction);

		// Go to tick
		DockingAction searchAction = new DockingAction("Search across space and time", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				String hex = self.plugin.getUserInputString("hex string", "hex string");
				if (hex != null && hex.length() > 0) {
					if(hex.length() % 2 != 0) {
						throw new IllegalArgumentException("requires even-length hex string");
					}
					byte[] str = new byte[hex.length()/2];
					for(int i = 0; i < hex.length(); i+=2) {
						str[i/2] = Byte.parseByte(hex.substring(i, i+2), 16);
					}
					MemSearchListingProvider p = new MemSearchListingProvider(self.plugin, str);
					p.addToTool();
					p.setVisible(true);
				}
			}
		};
		searchAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.viewstrings.provider"), null));
		searchAction.setEnabled(true);
		this.addLocalAction(searchAction);
	}

	private void createContextActions() {
		{
		GoToTickContextAction a = new GoToTickContextAction(this);
		a.setPopupMenuData(new MenuData(new String[] {"Go to tick"}, null, "addr"));
		this.plugin.getTool().addAction(a);
		}
	}
	
	@Override
	public ActionContext getActionContext(MouseEvent ev) {
		if(ev == null) {
			// something is asking for this without an actual click?
			return new MemoryListingActionContext(this, this.listingPanel.getCurrentField());			
		}
		java.awt.Point pt = ev.getPoint();
		FieldLocation floc = new FieldLocation();
		Field f = this.listingPanel.getFieldAt((int)pt.getX(), (int)pt.getY(), floc);
		if(f == null) {
			// we clicked but not on any particular field
			return new MemoryListingActionContext(this, this.listingPanel.getCurrentField());
		}
		return new MemoryListingActionContext(this, f);
	}
	
	@Override
	public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {
		if(field == null) return;
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
	public void showMemory(long start, long len, long tick) {
		HashMap<String, Long> params = new HashMap<>();
		params.put(MemoryListingView.VIEW_PARAM.ADDR_START.name(), start);
		params.put(MemoryListingView.VIEW_PARAM.LEN.name(), len);
		params.put(MemoryListingView.VIEW_PARAM.TICK.name(), tick);
		this.newView(new MemoryListingView(MemoryListingView.VIEW_TYPE.ADDR_WINDOW_VIEW.name(), params));
	}
	// Here begin the API functions to call the  
	public void setTick(long tick) {
		HashMap<String, Long> params = new HashMap<>();
		params.put(MemoryListingView.VIEW_PARAM.ADDR_START.name(), this.view.getViewParam(MemoryListingView.VIEW_PARAM.ADDR_START.name()));
		params.put(MemoryListingView.VIEW_PARAM.LEN.name(), this.view.getViewParam(MemoryListingView.VIEW_PARAM.LEN.name()));
		params.put(MemoryListingView.VIEW_PARAM.TICK.name(), tick);
		this.newView(new MemoryListingView(MemoryListingView.VIEW_TYPE.ADDR_WINDOW_VIEW.name(), params));
	}
	
	//---------------------------------------------------------------
	// Here begin the menu item action classes. 

	private class GoToTickContextAction extends AddrAction {
		public GoToTickContextAction(MemoryListingProvider provider) {
			super(provider, "Go to tick", provider.plugin.getName());
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, InputEvent.ALT_DOWN_MASK | InputEvent.CTRL_DOWN_MASK));
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(super.isEnabledForContext(context)) {
				MemoryListingActionContext tc = (MemoryListingActionContext) context; 
				if(isValidContext(tc)) {
					Field f = tc.getField();
					if(f != null && f instanceof MemoryListingAddrField) {
						return true;
					}
				}
			}
			return false;
		}
		
		@Override
		public void actionPerformed(ActionContext context) {
			System.out.println("accessors " + context.toString());
			MemoryListingActionContext tc = (MemoryListingActionContext) context; 
			Field f = tc.getField();
			SpacetimeTickField sf = (SpacetimeTickField) f;
			long tick = sf.getTick();
			provider.plugin.timeListingProvider.goToTick(tick);
		}
		
	}

	
	// A right-click menu action class should extend the PCAction class to be available 
	// whenever anything with a corresponding PC is right-clicked on  
	private abstract class AddrAction extends DockingAction {
		MemoryListingProvider provider;
		public AddrAction(MemoryListingProvider provider, String name, String owner) {
			super(name, owner);
			this.provider = provider;
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(context instanceof MemoryListingActionContext) {
				MemoryListingActionContext tc = (MemoryListingActionContext) context; 
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
			return context instanceof MemoryListingActionContext;
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
				Long pc = ((MemoryListingLayoutModel)this.model).getPCForIndex(idx);
				if(pc == null) continue;
				Address a = MadnessPlugin.flatApi.toAddr(pc);
				sel.add(a);
			}
		}
		ProgramSelection ps = new ProgramSelection(sel);
		this.plugin.codeViewer.getNavigatable().setSelection(ps);
	}
}

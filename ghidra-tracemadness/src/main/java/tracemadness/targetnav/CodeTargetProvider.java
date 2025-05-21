package tracemadness.targetnav;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextField;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import tracemadness.MadnessPlugin;

public class CodeTargetProvider extends ComponentProvider implements ActionContextProvider {

	private MadnessPlugin plugin;
	private JPanel mainPanel;
	JTextField startTickField;
	JTextField endTickField;
	JTextField startAddrField;
	JTextField endAddrField;
	JButton startTickButton;
	JButton endTickButton;
	JButton startAddrButton;
	JButton endAddrButton;
	
	JCheckBox timeSel;
	JCheckBox spaceSel;
	
	public Long startTick;
	public Long endTick;
	public Long startAddr;
	public Long endAddr;

	public CodeTargetProvider(MadnessPlugin plugin, String description) {
		super(MadnessPlugin.currentTool, description, plugin.getName());
		this.plugin = plugin;
		this.createDockingActions();
		this.startTick = 0L;
		this.endTick = 100L;
		
		this.startAddr = null;
		this.endAddr = null;
	}

	@Override
	public JComponent getComponent() {
		if (mainPanel == null) {
			buildPanel();
		}
		return mainPanel;
	}
	
	private void buildPanel() {
		CodeTargetProvider self = this;
		this.mainPanel = new JPanel();	
		
		GroupLayout layout = new GroupLayout(this.mainPanel);
		this.mainPanel.setLayout(layout);
		
		timeSel = new JCheckBox();
		spaceSel = new JCheckBox();

		timeSel.setSelected(false);
		spaceSel.setSelected(false);

		startTickButton = new JButton("Start Tick");
		endTickButton = new JButton("End Tick");
		
		startAddrButton = new JButton("Start PC");
		endAddrButton = new JButton("End PC");

		this.startTickField = new JTextField();
		this.endTickField = new JTextField();
		this.startAddrField = new JTextField();
		this.endAddrField = new JTextField();
		
		startTickField.setEnabled(false);
		endTickField.setEnabled(false);
		startTickButton.setEnabled(false);
		endTickButton.setEnabled(false);
		startAddrField.setEnabled(false);
		endAddrField.setEnabled(false);
		startAddrButton.setEnabled(false);
		endAddrButton.setEnabled(false);

		layout.setAutoCreateGaps(true);
		layout.setAutoCreateContainerGaps(true);

		layout.setHorizontalGroup(layout.createSequentialGroup()
				.addGroup(layout.createParallelGroup()
						.addComponent(timeSel)
						.addComponent(spaceSel))
				.addGroup(layout.createParallelGroup()
						.addComponent(startTickButton)
						.addComponent(startAddrButton))
				.addGroup(layout.createParallelGroup()
						.addComponent(startTickField)
						.addComponent(startAddrField))
				.addGroup(layout.createParallelGroup()
						.addComponent(endTickButton)
						.addComponent(endAddrButton))
				.addGroup(layout.createParallelGroup()
						.addComponent(endTickField)
						.addComponent(endAddrField)));
		layout.setVerticalGroup(layout.createSequentialGroup()
				.addGroup(layout.createParallelGroup()
						.addComponent(timeSel)
						.addComponent(startTickButton)
						.addComponent(startTickField)
						.addComponent(endTickButton)
						.addComponent(endTickField))
				.addGroup(layout.createParallelGroup()
						.addComponent(spaceSel)
						.addComponent(startAddrButton)
						.addComponent(startAddrField)
						.addComponent(endAddrButton)
						.addComponent(endAddrField)));

		timeSel.addActionListener(new AbstractAction("Time mode") {
			public void actionPerformed(ActionEvent ev) {
				startTickField.setEnabled(timeSel.isSelected());
				endTickField.setEnabled(timeSel.isSelected());
				startTickButton.setEnabled(timeSel.isSelected());
				endTickButton.setEnabled(timeSel.isSelected());
			}
		});
		
		spaceSel.addActionListener(new AbstractAction("Space mode") {
			public void actionPerformed(ActionEvent ev) {
				startAddrField.setEnabled(spaceSel.isSelected());
				endAddrField.setEnabled(spaceSel.isSelected());
				startAddrButton.setEnabled(spaceSel.isSelected());
				endAddrButton.setEnabled(spaceSel.isSelected());
			}
		});
		startAddrButton.addActionListener(new AbstractAction("Go to start addr") {
			public void actionPerformed(ActionEvent ev) {
				Address a = MadnessPlugin.flatApi.toAddr(startAddrField.getText());
				ProgramLocation loc = self.plugin.getProgramLocation(a, false);
				self.plugin.codeViewer.goTo(loc, true);
			}
		});
		endAddrButton.addActionListener(new AbstractAction("Go to end addr") {
			public void actionPerformed(ActionEvent ev) {
				Address a = MadnessPlugin.flatApi.toAddr(endAddrField.getText());
				ProgramLocation loc = self.plugin.getProgramLocation(a, false);
				self.plugin.codeViewer.goTo(loc, true);
			}
		});
		startTickButton.addActionListener(new AbstractAction("Go to start tick") {
			public void actionPerformed(ActionEvent ev) {
				Long tick = Long.parseLong(startTickField.getText());
				self.plugin.timeListingProvider.goToTick(tick);
			}
		});
		endTickButton.addActionListener(new AbstractAction("Go to end tick") {
			public void actionPerformed(ActionEvent ev) {
				Long tick = Long.parseLong(endTickField.getText());
				self.plugin.timeListingProvider.goToTick(tick);
			}
		});
		
	}

	private Long getStartAddr() {
		return MadnessPlugin.flatApi.toAddr(this.startAddrField.getText()).getOffset();
	}
	private Long getEndAddr() {
		return MadnessPlugin.flatApi.toAddr(this.endAddrField.getText()).getOffset();
	}

	private Long getStartTick() {
		return Long.parseLong(this.startTickField.getText());
	}
	private Long getEndTick() {
		return Long.parseLong(this.endTickField.getText());
	}
	
	private void createDockingActions() {

		CodeTargetProvider self = this;
		{
			// Go to tick
			DockingAction gotoAction = new DockingAction("Show accesses by code", getName()) {
				@Override
				public void actionPerformed(ActionContext arg0) {
					if(self.timeSel.isSelected() && self.spaceSel.isSelected()) {
						self.plugin.accessListingProvider.showAccessesInPCRect(self.getStartTick(),  self.getEndTick(), self.getStartAddr(), self.getEndAddr());
					} else if(self.timeSel.isSelected()) {
						self.plugin.accessListingProvider.showAccessesInTimeWindow(self.getStartTick(),  self.getEndTick());
					} else if(self.spaceSel.isSelected()) {
						self.plugin.accessListingProvider.showAccessesByPCRange(self.getStartAddr(), self.getEndAddr());
					}
				}
			};
			gotoAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.datatypes.filter.pointers.off"), null));
			gotoAction.setEnabled(true);
			this.addLocalAction(gotoAction);
		}
	}
	public void setStartTick(Long tick) {
		timeSel.setSelected(true);
		startTickField.setEnabled(true);
		endTickField.setEnabled(true);
		startTickButton.setEnabled(true);
		endTickButton.setEnabled(true);
		this.startTickField.setText(String.format("%d", tick));
	}
	public void setEndTick(Long tick) {
		timeSel.setSelected(true);
		startTickField.setEnabled(true);
		endTickField.setEnabled(true);
		startTickButton.setEnabled(true);
		endTickButton.setEnabled(true);
		this.endTickField.setText(String.format("%d", tick));
	}
	public void setStartAddr(Long addr) {
		spaceSel.setSelected(true);
		startAddrField.setEnabled(true);
		endAddrField.setEnabled(true);
		startAddrButton.setEnabled(true);
		endAddrButton.setEnabled(true);
		this.startAddrField.setText(MadnessPlugin.flatApi.toAddr(addr).toString());
	}
	public void setEndAddr(Long addr) {
		spaceSel.setSelected(true);
		startAddrField.setEnabled(true);
		endAddrField.setEnabled(true);
		startAddrButton.setEnabled(true);
		endAddrButton.setEnabled(true);
		this.endAddrField.setText(MadnessPlugin.flatApi.toAddr(addr).toString());
	}
}

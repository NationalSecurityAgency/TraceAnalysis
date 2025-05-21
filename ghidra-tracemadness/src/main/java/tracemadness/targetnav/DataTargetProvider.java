package tracemadness.targetnav;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import tracemadness.MadnessPlugin;
import tracemadness.objectdata.ObjectInfo;

public class DataTargetProvider extends ComponentProvider implements ActionContextProvider {

	private MadnessPlugin plugin;
	private JPanel mainPanel;
	JTextField startTickField;
	JTextField endTickField;
	JTextField startAddrField;
	JTextField endAddrField;
	JTextField sizeField;
	
	public Long startTick;
	public Long endTick;
	public Long startAddr;
	public Long endAddr;

	public DataTargetProvider(MadnessPlugin plugin, String description) {
		super(MadnessPlugin.currentTool, description, plugin.getName());
		this.plugin = plugin;
		this.createDockingActions();
		this.startTick = 0L;
		this.endTick = 100L;
		
		this.startAddr = 0L;
		this.endAddr = 100L;
	}

	@Override
	public JComponent getComponent() {
		if (mainPanel == null) {
			buildPanel();
		}
		return mainPanel;
	}
	
	private void buildPanel() {
		DataTargetProvider self = this;
		this.mainPanel = new JPanel();	
		
		GroupLayout layout = new GroupLayout(this.mainPanel);
		this.mainPanel.setLayout(layout);

		JButton startTickButton = new JButton("Start Tick");
		JButton endTickButton = new JButton("End Tick");
		
		JButton startAddrButton = new JButton("Start Addr");
		JButton endAddrButton = new JButton("End Addr");

		this.startTickField = new JTextField();
		this.endTickField = new JTextField();
		this.startAddrField = new JTextField();
		this.endAddrField = new JTextField();
		this.sizeField = new JTextField();

		startAddrField.getDocument().addDocumentListener(new DocumentListener() {
			  public void changedUpdate(DocumentEvent e) {
			    change();
			  }
			  public void removeUpdate(DocumentEvent e) {
			    change();
			  }
			  public void insertUpdate(DocumentEvent e) {
			    change();
			  }

			  public void change() {
				  try {
					  Address start = MadnessPlugin.flatApi.toAddr(startAddrField.getText());
					  Address end = MadnessPlugin.flatApi.toAddr(endAddrField.getText());
					  sizeField.setText(String.format("%d",end.getOffset()-start.getOffset()));
				  } catch(Exception e) {
					  // JOptionPane.showMessageDialog(null, "", JOptionPane.ERROR_MESSAGE) 
				  }
			  }	
			});
		endAddrField.getDocument().addDocumentListener(new DocumentListener() {
			  public void changedUpdate(DocumentEvent e) {
			    change();
			  }
			  public void removeUpdate(DocumentEvent e) {
			    change();
			  }
			  public void insertUpdate(DocumentEvent e) {
			    change();
			  }

			  public void change() {
				  try {
					  Address start = MadnessPlugin.flatApi.toAddr(startAddrField.getText());
					  Address end = MadnessPlugin.flatApi.toAddr(endAddrField.getText());
					  sizeField.setText(String.format("%d",end.getOffset()-start.getOffset()));
				  } catch(Exception e) {
					  // JOptionPane.showMessageDialog(null, "", JOptionPane.ERROR_MESSAGE) 
				  }
			  }	
			});
		sizeField.getDocument().addDocumentListener(new DocumentListener() {
			  public void changedUpdate(DocumentEvent e) {
			    change();
			  }
			  public void removeUpdate(DocumentEvent e) {
			    change();
			  }
			  public void insertUpdate(DocumentEvent e) {
			    change();
			  }

			  public void change() {
				  try {
					  Address start = MadnessPlugin.flatApi.toAddr(startAddrField.getText());
					  long sz = Long.parseLong(sizeField.getText());
					  Address end = start.add(sz);
					  endAddrField.setText(end.toString());
				  } catch(Exception e) {
					  // JOptionPane.showMessageDialog(null, "", JOptionPane.ERROR_MESSAGE) 
				  }
			  }	
			});
		
		layout.setAutoCreateGaps(true);
		layout.setAutoCreateContainerGaps(true);

		layout.setHorizontalGroup(layout.createSequentialGroup()
				.addGroup(layout.createParallelGroup()
						.addComponent(startTickButton)
						.addComponent(endTickButton))
				.addGroup(layout.createParallelGroup()
						.addComponent(startTickField)
						.addComponent(endTickField))
				.addGroup(layout.createParallelGroup()
						.addComponent(startAddrButton))
				.addGroup(layout.createParallelGroup()
						.addComponent(startAddrField))
				.addGroup(layout.createParallelGroup()
						.addComponent(endAddrButton))
				.addGroup(layout.createParallelGroup()
						.addComponent(endAddrField))
				.addGroup(layout.createParallelGroup()
						.addComponent(sizeField)));
		layout.setVerticalGroup(layout.createSequentialGroup()
				.addGroup(layout.createParallelGroup()
						.addComponent(startTickButton)
						.addComponent(startTickField))
				.addGroup(layout.createParallelGroup()
						.addComponent(endTickButton)
						.addComponent(endTickField))
				.addGroup(layout.createParallelGroup()
						.addComponent(startAddrButton)
						.addComponent(startAddrField)
						.addComponent(endAddrButton)
						.addComponent(endAddrField)
						.addComponent(sizeField)));

		startAddrButton.addActionListener(new AbstractAction("Go to start addr") {
			public void actionPerformed(ActionEvent ev) {
				try {
					Long start = MadnessPlugin.flatApi.toAddr(startAddrField.getText()).getOffset();
					Long tick = Long.parseLong(startTickField.getText());
					self.plugin.memoryListingProvider.showMemory(start-100, 200, tick);
				} catch(Exception e) {
					
				}
			}
		});
		endAddrButton.addActionListener(new AbstractAction("Go to end addr") {
			public void actionPerformed(ActionEvent ev) {
				try {
					Long tick = Long.parseLong(startTickField.getText());
					Long end = Long.parseLong(endAddrField.getText());
					self.plugin.memoryListingProvider.showMemory(end-100, 200, tick);
				} catch(Exception e) {
					
				}
			}
		});
		startTickButton.addActionListener(new AbstractAction("Go to start tick") {
			public void actionPerformed(ActionEvent ev) {
				try {
					Long tick = Long.parseLong(startTickField.getText());
					self.plugin.timeListingProvider.goToTick(tick);
					Long start = MadnessPlugin.flatApi.toAddr(startAddrField.getText()).getOffset();
					Long end = MadnessPlugin.flatApi.toAddr(endAddrField.getText()).getOffset();
					self.plugin.memoryListingProvider.showMemory(start, end-start, tick);
				} catch(Exception e) {
					
				}
			}
		});
		endTickButton.addActionListener(new AbstractAction("Go to end tick") {
			public void actionPerformed(ActionEvent ev) {
				try {
					Long tick = Long.parseLong(endTickField.getText());
					self.plugin.timeListingProvider.goToTick(tick);
					Long start = MadnessPlugin.flatApi.toAddr(startAddrField.getText()).getOffset();
					Long end = MadnessPlugin.flatApi.toAddr(endAddrField.getText()).getOffset();
					self.plugin.memoryListingProvider.showMemory(start, end-start, tick);
				} catch(Exception e) {
					
				}
			}
		});
		
	}
	
	public Long getStartAddr() {
		return MadnessPlugin.flatApi.toAddr(startAddrField.getText()).getOffset();
	}
	public Long getEndAddr() {
		return MadnessPlugin.flatApi.toAddr(endAddrField.getText()).getOffset();
	}
	public Long getStartTick() {
		return Long.parseLong(this.startTickField.getText());
	}
	public Long getEndTick() {
		return Long.parseLong(this.endTickField.getText());
	}
	private void createDockingActions() {

		DataTargetProvider self = this;
		{
			// Go to tick
			DockingAction gotoAction = new DockingAction("Show accesses of region", getName()) {
				@Override
				public void actionPerformed(ActionContext arg0) {
					self.plugin.accessListingProvider.showAccessesInRect(self.getStartTick(), self.getEndTick(), self.getStartAddr(), self.getEndAddr());
				}
			};
			gotoAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.datatypes.filter.pointers.off"), null));
			gotoAction.setEnabled(true);
			this.addLocalAction(gotoAction);
		}
		{
			// Create object of new type
			DockingAction createObjectNewTypeAction = new DockingAction("Create object with new type from region", getName()) {
				@Override
				public void actionPerformed(ActionContext arg0) {
					Long _startTick = self.getStartTick();
					Long _endTick = self.getEndTick();
					Long _startAddr = self.getStartAddr();
					Long _endAddr = self.getEndAddr();

					String typename = self.plugin.getUserInputString("typename", "typename");
					if (typename == null)
						return;
					String name = self.plugin.getUserInputString("name", "name");
					if (name == null)
						return;
					int sz = (int)(_endAddr-_startAddr);
					
					StructureDataType ty = new StructureDataType(typename, sz);
					DataTypeManager mgr = self.plugin.getDataTypeManager();
					if(mgr == null) {
						return;
					}
					int txid = mgr.startTransaction("adding new type");
					mgr.addDataType(ty, null);
					mgr.endTransaction(txid, true);
					long size = sz;
					DataType newType = mgr.getDataType("/" + ty.getName());
					ObjectInfo obj = new ObjectInfo(String.format("%d_%d", _startTick, _startAddr), name, size, _startAddr, _startTick, _endTick, newType);

					self.plugin.madness.setObject(obj);
					self.plugin.objectManagerProvider.model.reload();
				}
			};
			createObjectNewTypeAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.symboltable.provider"), null));
			createObjectNewTypeAction.setEnabled(true);
			this.addLocalAction(createObjectNewTypeAction);
		}

		{
			// Create object of existing type
			DockingAction createObjectTypeAction = new DockingAction("Create object of known type from region", getName()) {
				@Override
				public void actionPerformed(ActionContext arg0) {
					Long _startTick = self.getStartTick();
					Long _endTick = self.getEndTick();
					Long _startAddr = self.getStartAddr();
					Long _endAddr = self.getEndAddr();

					DataType ty = self.plugin.getUserInputDataType();
					if (ty == null)
						return;
					String name = self.plugin.getUserInputString("name", "name");
					if (name == null)
						return;
					int sz = ty.getLength();
					if(_endAddr-_startAddr != sz) {
						String ok = self.plugin.getUserInputString(String.format("Size mismatch: given size = %d but %s size is %d. Continue?", _endAddr-_startAddr, ty.getName(), sz), "Continue?");
						if(ok == null) {
							return;
						}
					}
					DataTypeManager mgr = self.plugin.getDataTypeManager();
					if(mgr == null) {
						return;
					}
					int txid = mgr.startTransaction("adding new type");
					mgr.addDataType(ty, null);
					mgr.endTransaction(txid, true);
					long size = sz;
					DataType newType = mgr.getDataType("/" + ty.getName());
					ObjectInfo obj = new ObjectInfo(String.format("%d_%d", _startTick, _startAddr), name, size, _startAddr, _startTick, _endTick, newType);

					self.plugin.madness.setObject(obj);
					self.plugin.objectManagerProvider.model.reload();
				}
			};
			createObjectTypeAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.datatypes.default"), null));
			createObjectTypeAction.setEnabled(true);
			this.addLocalAction(createObjectTypeAction);
		}
	}
	private void updateSize() {
		try {
			long size = getEndAddr()-getStartAddr();
			sizeField.setText(String.format("%d", size));
		} catch(Exception e) {
			// do nothing
		}
	}
	public void setStartTick(Long tick) {
		this.startTickField.setText(String.format("%d", tick));
	}
	public void setEndTick(Long tick) {
		this.endTickField.setText(String.format("%d", tick));
	}
	public void setStartAddr(Long addr) {
		this.startAddrField.setText(MadnessPlugin.flatApi.toAddr(addr).toString());
		this.updateSize();
	}
	public void setEndAddr(Long addr) {
		this.endAddrField.setText(MadnessPlugin.flatApi.toAddr(addr).toString());
		this.updateSize();
	}
}

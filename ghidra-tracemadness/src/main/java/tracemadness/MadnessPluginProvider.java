package tracemadness;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.json.JSONArray;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import java.nio.file.Path;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import resources.Icons;
import tracemadness.accessmap.AccessMapProvider;
import tracemadness.calltree.CallTreeProvider;
import tracemadness.modulemap.ModuleMapProvider;
import tracemadness.objectmanager.ObjectManagerProvider;
import tracemadness.settings.Setting;
import tracemadness.settings.SettingsProvider;
import tracemadness.spacelisting.SpaceListingProvider;
import tracemadness.timelisting.TimeListingProvider;

public class MadnessPluginProvider extends ComponentProvider {
	private JPanel mainPanel;
	private MadnessPlugin plugin;
	protected JComboBox<String> databaseDropdown;

	public MadnessPluginProvider(MadnessPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		buildPanel();
		buildDockingActions();
	}

	// Customize GUI
	private JPanel buildPanel() {
		mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout());
		mainPanel.add(createMainPanel(), BorderLayout.CENTER);
		databaseDropdown = createDropdown();
		mainPanel.add(databaseDropdown, BorderLayout.NORTH);
		setVisible(true);
		return mainPanel;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	private JPanel createMainPanel() {
		JPanel p = new JPanel(new GridLayout(6, 1));
		JButton instructionListingButton = new JButton(INSTRUCTION_LISTING_BUTTON);
		JButton accessMapButton = new JButton(ACCESS_MAP_BUTTON);
		JButton spaceListingButton = new JButton(SPACE_LISTING_BUTTON);
		JButton objectsButton = new JButton(OBJECTS_BUTTON);
		JButton calltreeButton = new JButton(CALL_TREE_BUTTON);
		JButton highlightButton = new JButton(HIGHLIGHT_BUTTON);
		JButton importStructsButton = new JButton(IMPORT_STRUCTS_BUTTON);
		JButton moduleMapButton = new JButton(MODULES_BUTTON);

		int w = 400;
		instructionListingButton.setPreferredSize(new Dimension(w, 30));
		accessMapButton.setPreferredSize(new Dimension(w, 30));
		spaceListingButton.setPreferredSize(new Dimension(w, 30));
		objectsButton.setPreferredSize(new Dimension(w, 30));
		calltreeButton.setPreferredSize(new Dimension(w, 30));
		highlightButton.setPreferredSize(new Dimension(w, 30));
		importStructsButton.setPreferredSize(new Dimension(w, 30));
		moduleMapButton.setPreferredSize(new Dimension(w, 30));
		
		p.add(instructionListingButton);
		p.add(accessMapButton);
		p.add(spaceListingButton);
		p.add(objectsButton);
		p.add(calltreeButton);
		p.add(highlightButton);
		p.add(importStructsButton);
		p.add(moduleMapButton);
		return p;
	}

	private JComboBox<String> createDropdown() {
		String[] availableDbs = plugin.madness.getAllDBs().toArray(new String[0]);

		JComboBox<String> dropdown = new JComboBox<String>(availableDbs);
		dropdown.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JComboBox<?> box = (JComboBox<?>) e.getSource();
				String db = (String) box.getSelectedItem();
				plugin.madness.selectDB(db);
				plugin.databaseSetting.setValue(db);
			}
		});
		return dropdown;
	}

	private void buildDockingActions() {
		DockingAction settings = new DockingAction("Settings", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {

				List<Setting> settingsList = new ArrayList<Setting>();
				//for logging checkbox if wanted // settings.add(plugin.loggingSetting);
				settingsList.add(plugin.colorSetting);
				settingsList.add(plugin.sliceDepthSetting);

				SettingsProvider provider = new SettingsProvider(plugin.getTool(), "Settings", getName(), settingsList);
				provider.addToTool();
				provider.setVisible(true);
			}
		};
		settings.setToolBarData(new ToolBarData(Icons.MAKE_SELECTION_ICON, null));
		settings.setEnabled(true);
		this.addLocalAction(settings);
	}

	@SuppressWarnings("serial")
	public final AbstractAction INSTRUCTION_LISTING_BUTTON = new AbstractAction("Instruction Listing") {
		public void actionPerformed(ActionEvent ev) {
			if (plugin.timeListingProvider == null) {
				plugin.timeListingProvider = new TimeListingProvider(plugin, "Instruction Listing");
				plugin.timeListingProvider.addToTool();
			}
			plugin.timeListingProvider.setVisible(true);
		}
	};

	@SuppressWarnings("serial")
	public final AbstractAction MODULES_BUTTON = new AbstractAction("Module Map") {
		public void actionPerformed(ActionEvent ev) {
			if (plugin.moduleMapProvider == null) {
				plugin.moduleMapProvider = new ModuleMapProvider(plugin, "Module Map", plugin.moduleMap);
				plugin.moduleMapProvider.addToTool();
			}
			plugin.moduleMapProvider.setVisible(true);
		}
	};

	@SuppressWarnings("serial")
	public final AbstractAction ACCESS_MAP_BUTTON = new AbstractAction("Access Map") {
		public void actionPerformed(ActionEvent ev) {
			if (plugin.accessMapProvider == null) {
				plugin.accessMapProvider = new AccessMapProvider(plugin, "Access Map");
				plugin.accessMapProvider.addToTool();
			}
			plugin.accessMapProvider.setVisible(true);
		}
	};

	@SuppressWarnings("serial")
	public final AbstractAction SPACE_LISTING_BUTTON = new AbstractAction("Space Listing") {
		public void actionPerformed(ActionEvent ev) {
			if (plugin.spaceListingProvider == null) {
				plugin.spaceListingProvider = new SpaceListingProvider(plugin, "Space Listing");
				plugin.spaceListingProvider.addToTool();
			}
			plugin.spaceListingProvider.setVisible(true);
		}
	};

	@SuppressWarnings("serial")
	public final AbstractAction OBJECTS_BUTTON = new AbstractAction("Object Manager") {
		public void actionPerformed(ActionEvent ev) {
			if (plugin.objectManagerProvider == null) {
				plugin.objectManagerProvider = new ObjectManagerProvider(plugin, "Objects");
				plugin.objectManagerProvider.addToTool();
			}
			plugin.objectManagerProvider.setVisible(true);
		}
	};

	@SuppressWarnings("serial")
	public final AbstractAction CALL_TREE_BUTTON = new AbstractAction("Call Tree") {
		public void actionPerformed(ActionEvent ev) {
			if(plugin.calltreeProvider == null) {
				plugin.calltreeProvider = new CallTreeProvider(plugin);
				plugin.calltreeProvider.addToTool();
			}
			plugin.calltreeProvider.setVisible(true);
		}
	};

	@SuppressWarnings("serial")
	public final AbstractAction HIGHLIGHT_BUTTON = new AbstractAction("Toggle Highlight Trace") {
		public void actionPerformed(ActionEvent ev) {
			if (plugin.shouldHighlight) {
				plugin.shouldHighlight = false;
				plugin.clearColor();
			} else {
				plugin.shouldHighlight = true;
				plugin.colorTrace();
				
			}
		}
	};

	private class NewStruct {
		public String name;
		public int size;
		public ArrayList<StructEntry> entries;
		public NewStruct(String name, int size) {
			this.name = name;
			this.size = size;
			this.entries = new ArrayList<>();
		}
		public void addEntry(StructEntry e) {
			this.entries.add(e);
		}
	}
	
	private class StructEntry {
		public int size;
		public int offset;
		public String name;
		public String comment;
		public StructEntry(int size, int offset, String name, String comment) {
			this.size = size;
			this.offset = offset;
			this.name = name;
			this.comment = comment;
		}
		public DataType getDataType(DataTypeManager mgr) {
			switch (this.size) {
				case 1:
					return new CharDataType();
				case 2:
					return new ShortDataType();
				case 4:
					return new IntegerDataType();
				case 8:
					return new LongLongDataType();
			}
			return new ArrayDataType(new CharDataType(), this.size, 1);
		}
	}
	
	@SuppressWarnings("serial")
	public final AbstractAction IMPORT_STRUCTS_BUTTON = new AbstractAction("Import Structures") {
		public void actionPerformed(ActionEvent ev) {
			File f = plugin.getUserInputFile();
			if(f == null) {
				return;
			}
			try {
				ArrayList<NewStruct> structs = new ArrayList<>();
				if(f.getName().endsWith("xml")) {
					DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
					DocumentBuilder d = factory.newDocumentBuilder();
					Document doc = d.parse(f);
					Element root = doc.getDocumentElement();
					if(root.getTagName() != "structs") {
						System.out.println("Could not find element /structs");
						return;
					}
					NodeList structElts = root.getElementsByTagName("struct");
					for(int i = 0 ; i < structElts.getLength(); i++) {	
						Element structElt = (Element)structElts.item(i);
						if(!structElt.hasAttribute("name")) {
							System.out.printf("Missing /structs/struct[%d]/@name\n", i);
							return;
						}
						if(!structElt.hasAttribute("size")) {
							System.out.printf("Missing /structs/struct[%d]/@size\n", i);
							return;
						}
						String name = structElt.getAttribute("name");
						int size = Integer.parseInt(structElt.getAttribute("size"));
						NewStruct newStruct = new NewStruct(name, size);
						structs.add(newStruct);
						NodeList structFields = structElt.getElementsByTagName("field");
						for(int j = 0; j < structFields.getLength(); j++) {
							Element fe = (Element)structFields.item(j);
							if(!fe.hasAttribute("size")) {
								System.out.printf("Missing /structs/struct[%d]/field[%d]@size\n", i, j);
								return;
							}
							if(!fe.hasAttribute("name")) {
								System.out.printf("Missing /structs/struct[%d]/field[%d]@name\n", i, j);
								return;
							}
							if(!fe.hasAttribute("offset")) {
								System.out.printf("Missing /structs/struct[%d]/field[%d]@offset\n", i, j);
								return;
							}
							String fname = fe.getAttribute("name");
							int fsize = Integer.parseInt(fe.getAttribute("size"));
							int offset = Integer.parseInt(fe.getAttribute("offset"));
							String comment = "";
							if(fe.hasAttribute("value")) {
								comment = fe.getAttribute("value");
							}
							newStruct.addEntry(new StructEntry(fsize, offset, fname, comment));
						}
					}
				} else if(f.getName().endsWith("json")) {
					String data = Files.readString(Path.of(f.getAbsolutePath()));
					JSONObject o = new JSONObject(data);
					if(o.has("structures")) {
						JSONArray a = o.getJSONArray("structures");
						for(int i = 0; i < a.length(); i++) {
							JSONObject s = a.getJSONObject(i);
							if(!s.has("name")) {
								System.out.printf("Missing /structures/struct[%d]/name\n", i);
								return;
							}
							if(!s.has("size")) {
								System.out.printf("Missing /structures/struct[%d]/size\n", i);
								return;
							}
							NewStruct newStruct = new NewStruct(s.getString("name"), s.getInt("size"));
							structs.add(newStruct);
							if(!s.has("fields")) continue;
							JSONArray fs = s.getJSONArray("fields");
							for(int j = 0; j < fs.length(); j++) {
								JSONObject fo = fs.getJSONObject(j);
								if(!fo.has("offset")) {
									System.out.printf("Missing /structures/struct[%d]/fields[%d]/offset\n", i, j);
									return;
								}
								if(!fo.has("size")) {
									System.out.printf("Missing /structures/struct[%d]/fields[%d]/size\n", i, j);
									return;
								}
								if(!fo.has("name")) {
									System.out.printf("Missing /structures/struct[%d]/fields[%d]/name\n", i, j);
									return;
								}
								String comment = "";
								if(fo.has("value")) {
									comment = fo.getString("value");
								}
								newStruct.addEntry(new StructEntry(fo.getInt("offset"), fo.getInt("size"), fo.getString("name"), comment));
							}
						}
					} else {
						System.out.println("missing: /structures");
						return;
					}
				} else {
					System.out.println("Unknown file type: " + f.getName());
					return;
				}
				for(NewStruct ns : structs) {
					DataTypeManager mgr = MadnessPlugin.programManager.getCurrentProgram().getDataTypeManager();
					StructureDataType s = new StructureDataType(ns.name, ns.size);
					for(StructEntry e : ns.entries) {
						DataType ty = e.getDataType(mgr);
						s.replaceAtOffset(e.offset, ty, e.size, e.name, e.comment);
					}
					int txid = mgr.startTransaction("add " + ns.name);
					mgr.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);
					mgr.endTransaction(txid, true);
				}
			} catch(Exception e) {
				e.printStackTrace();
				return;
			}
		}
	};

}
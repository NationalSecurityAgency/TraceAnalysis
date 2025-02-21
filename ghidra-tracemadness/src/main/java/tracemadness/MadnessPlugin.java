/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package tracemadness;

import java.awt.Color;
import java.io.File;
import java.util.HashMap;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.json.JSONObject;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.dialogs.InputDialog;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.MarkerService;
import ghidra.app.services.MarkerSet;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.OptionType;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import tracemadness.objectdata.ObjectCache;
import tracemadness.objectmanager.ObjectManagerProvider;
import tracemadness.settings.Setting;
import tracemadness.spacelisting.SpaceListingProvider;
import tracemadness.timelisting.TimeListingProvider;
import tracemadness.modulemap.ModuleInfo;
import tracemadness.modulemap.ModuleMap;
import tracemadness.modulemap.ModuleMapProvider;
import tracemadness.accessmap.AccessMapProvider;
import tracemadness.calltree.CallTreeProvider;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
		status = PluginStatus.UNSTABLE,
		packageName = MiscellaneousPluginPackage.NAME,
		category = PluginCategoryNames.MISC,
		shortDescription = "a DataFlow helper",
		description = "TraceMadness allows you to explore program execution inside the Ghidra framework from recorded traces using Dataflow databases."
		)
//@formatter:on
public class MadnessPlugin extends ProgramPlugin implements MadnessQueryResultListener {
	public static final org.apache.logging.log4j.Logger LOG = LogManager.getLogger(MadnessPlugin.class);
	static MadnessPluginProvider provider;

	public TimeListingProvider timeListingProvider;
	public AccessMapProvider accessMapProvider;
	public SpaceListingProvider spaceListingProvider;
	public ObjectManagerProvider objectManagerProvider;
	public ModuleMapProvider moduleMapProvider;

	public ArangoClient madness = null;
	public ObjectCache objectCache;
	public ModuleMap moduleMap;
	
	public DecompInterface decomp;
	public HashMap<Address, HighFunction> decompCache;

	public static PluginTool currentTool;
	public static FlatProgramAPI flatApi;
	private static Program program;

	public CodeViewerService codeViewer;
	public static ColorizingService coloriser;

	public Setting databaseSetting;
	public Setting colorSetting;
	//for logging checkbox if wanted // public Setting loggingSetting;
	public Setting isColoredSetting;
	public Setting sliceDepthSetting;
	public static ProgramManager programManager;
	public Long minTick;
	public Long maxTick;
	public Boolean shouldHighlight;
	public DataTypeManager dataTypeManager;
	public CallTreeProvider calltreeProvider;
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 * @throws Exception
	 */
	public MadnessPlugin(PluginTool tool) throws Exception {
		super(tool);
		MadnessPlugin.currentTool = tool;
		madness = new ArangoClient();
		programManager = tool.getService(ProgramManager.class);
		decomp = new DecompInterface();
		decompCache = new HashMap<Address, HighFunction>();
		moduleMap = null;
		shouldHighlight = false;
		dataTypeManager = null;

		createSettings();
	}
	
	public static ProgramManager getProgramManager() {
		return MadnessPlugin.currentTool.getService(ProgramManager.class);
	}
	
	public DataTypeManager getDataTypeManager() {
		if(this.dataTypeManager != null) {
			return this.dataTypeManager;
		}
		//File gdt = new File("/tm.gdt");
	    //this.dataTypeManager = FileDataTypeManager.openFileArchive(gdt, false);
		DomainFolder root = tool.getProjectManager().getActiveProject().getProjectData().getFolder("/");
		DomainFile archiveFile = root.getFile("tracemadness");
		DataTypeArchiveDB archive;
		if(archiveFile == null) {
			try {
				archive = new DataTypeArchiveDB(root, "tracemadness", currentProgram);
				this.dataTypeManager = archive.getDataTypeManager();
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			try {
				if(archiveFile.isOpen() || archiveFile.checkout(true, null)) {
					DomainObject obj = archiveFile.getOpenedDomainObject(tool);
					archive = ((ghidra.program.database.DataTypeArchiveDB)obj);
					if(archive != null) {
						this.dataTypeManager = archive.getDataTypeManager();
					}				
				}
			} catch(Exception e) {
				e.printStackTrace();
			}
		}
		return this.dataTypeManager;

	}
	
	public ObjectCache getObjectCache() {
		if(objectCache == null) {
			objectCache = new ObjectCache(this.getDataTypeManager(), this);
			objectCache.refresh();
		}
		return objectCache;
	}
	
	@Override
	protected void programActivated(Program p) {
		MadnessPlugin.program = p;
		MadnessPlugin.flatApi = new FlatProgramAPI(program);
		
		//we create the object manager here so that the data type manager 
		// is accessible, which is not the case unless a program is active
		if(objectCache == null) {
			objectCache = new ObjectCache(p.getDataTypeManager(), this);
			objectCache.refresh();
		}

		if(moduleMap == null) {
			moduleMap = new ModuleMap(this);
			moduleMap.refresh();
		}
		
		String db = (String) this.databaseSetting.getValue();
		if (db != null && !db.equals("")) {
			madness.selectDB(db);
			provider.databaseDropdown.setSelectedItem(db);
		}
	}
	

	public String getUserInputString(String title, String label) {
		InputDialog prompt = new InputDialog(title, label, null);
		MadnessPlugin.currentTool.showDialog(prompt);
		if (prompt.isCanceled())
			return null;
		return prompt.getValue();
	}

	public Long getUserInputLong(String title, String label) {
		InputDialog prompt = new InputDialog(title, label, null);
		MadnessPlugin.currentTool.showDialog(prompt);
		if (prompt.isCanceled())
			return null;
		String s = prompt.getValue();
		if (s.startsWith("0x")) {
			return Long.parseUnsignedLong(s.substring(2), 16);
		}
		return Long.parseUnsignedLong(s);
	}
	
	public DataType getUserInputDataType() {
		DataTypeSelectionDialog dialog = new DataTypeSelectionDialog(MadnessPlugin.currentTool, MadnessPlugin.program.getDataTypeManager(), -1, AllowedDataTypes.ALL);
		MadnessPlugin.currentTool.showDialog(dialog);
		DataType dataType = dialog.getUserChosenDataType();
		return dataType;
	}
	
	public File getUserInputFile() {
        GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText("Select");
        chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
        chooser.setTitle("Select Structure Definition File (json or xml)");
        File file = chooser.getSelectedFile();
        return file;
	}

	@Override
	public void init() {
		super.init();
		provider = new MadnessPluginProvider(this, getName());
		codeViewer = getTool().getService(CodeViewerService.class);
		coloriser = this.getTool().getService(ColorizingService.class);
	}

	private void createSettings() {

		this.databaseSetting = new Setting("Default Database", OptionType.STRING_TYPE, MadnessPlugin.currentTool);
		//for logging checkbox if wanted //this.loggingSetting = new Setting("Logging Output", OptionType.BOOLEAN_TYPE, MadnessPlugin.currentTool);
		this.colorSetting = new Setting("Trace Color", OptionType.COLOR_TYPE, MadnessPlugin.currentTool);
		this.isColoredSetting = new Setting("Is Colored", OptionType.BOOLEAN_TYPE, MadnessPlugin.currentTool);
		this.sliceDepthSetting = new Setting("Slice Depth", OptionType.INT_TYPE, MadnessPlugin.currentTool);
		if (sliceDepthSetting.getValue() == null) {
			sliceDepthSetting.setValue(20);
		}
	}

	public void runQuery(String queryName, String[] queryParams, MadnessQueryResultListener listener, String queryTag) {
		MadnessQuery q = this.madness.getQuery(queryName);
		if(q == null) {
			return;
		}
		try {
			MadnessQueryCommand cmd = new MadnessQueryCommand(q, queryParams, this.madness.getCurrentDB(), listener, queryTag);
			this.getTool().executeBackgroundCommand(cmd, this.getCurrentProgram());
		} catch(Exception exc) {
			MadnessPlugin.LOG.error(exc.getMessage());
		}
	}
	
	public void queryCompleted(List<JSONObject> results, String tag) {
		MadnessPlugin self = this;
		if(tag.equals("color")) {
			Swing.runLater(new Runnable() {
				public void run() {

					Color addrColor = (Color) colorSetting.getValue();
					if (addrColor == null) {
						addrColor = coloriser.getColorFromUser(null);
						colorSetting.setValue(addrColor);
					}
			
					MarkerService ms = tool.getService(MarkerService.class);
					HashMap<String, MarkerSet> markerSetCache = new HashMap<>();
					List<JSONObject> traceInstructions = results;
					for (int i = 0; i < traceInstructions.size(); i++) {
						Address a = MadnessPlugin.flatApi.toAddr(Long.toHexString(traceInstructions.get(i).getLong("pc")));
						ProgramLocation loc = self.getProgramLocation(a, false);
						if(loc == null) continue;
						String path = loc.getProgram().getDomainFile().getPathname();
						MarkerSet msms;
						if(markerSetCache.containsKey(path)) {
							msms = markerSetCache.get(path);
						} else {
							msms = ms.getMarkerSet("TraceMadnessHighlight", loc.getProgram());
							if (msms == null) {
								msms = ms.createAreaMarker("TraceMadnessHighlight", "highlight of code run in Dataflow recording", MadnessPlugin.program, 999         , false       , true          , true           , addrColor           , true);
							}
							markerSetCache.put(path,  msms);
						}
						msms.add(loc.getAddress());
					}
				}
			});
		}
	}
	
	public void colorTrace() {
		this.runQuery("coverage", new String[] {}, this, "color");
	}

	public void clearColor() {
		Swing.runLater(new Runnable() {
			public void run() {
				MarkerService ms = tool.getService(MarkerService.class);
				MarkerSet  msms = ms.getMarkerSet("TraceMadnessHighlight", MadnessPlugin.program);
				if (msms != null) {
					msms.clearAll();
				}
			}
		});
			
	}
	
	public ProgramLocation getProgramLocation(Address addr, boolean takeFocus) {
		ModuleInfo m = this.moduleMap.getContainingModule(addr.getOffset());
		if(m == null) return null;
		DomainFile f = this.getTool().getProject().getProjectData().getFile(m.getPath());
		Program p = getProgramManager().openProgram(f, DomainFile.DEFAULT_VERSION, takeFocus ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_HIDDEN);
		addr = addr.add(-m.getBase()).add(p.getImageBase().getUnsignedOffset());
		return new ProgramLocation(p, addr);
	}
	
	public Function getFunctionContaining(Address addr) {
		ProgramLocation loc = this.getProgramLocation(addr, false);
		return loc.getProgram().getFunctionManager().getFunctionContaining(loc.getAddress());
	}
}

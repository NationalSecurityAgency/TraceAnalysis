package tracemadness.modulemap;

import java.lang.Long;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.json.JSONObject;

import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;

public class ModuleMap implements MadnessQueryResultListener {

	private TreeMap<Long, ModuleInfo> modules;
	private TreeMap<String, ModuleInfo> modulesByPath;
	MadnessPlugin plugin;
	
	public ModuleMap(MadnessPlugin plugin) {
		this.plugin = plugin;
		this.modules = new TreeMap<>();
		this.modulesByPath = new TreeMap<>();
	}

	public ModuleInfo getContainingModule(Long addr) {
		Map.Entry<Long, ModuleInfo> e = this.modules.floorEntry(addr);
		ModuleInfo m = e.getValue();
		if(addr < m.getBase() + m.getSize() && m.getBase() <= addr) {
			return m;
		}
		return null;
	}
	
	public Long getAbsolute(String path, Long offset) {
		ModuleInfo mod = getModuleByPath(path);
		if(mod == null) {
			return null;
		}
		return mod.getBase() + offset;
	}
	
	public ModuleInfo getModuleByPath(String path) {
		return modulesByPath.get(path);
	}
	
	public void refresh() {
		try {
			plugin.runQuery("modules", new String[] {}, this, "modules");
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	@Override
	public void queryCompleted(List<JSONObject> results, String tag ) {
		if(tag.equals("modules")) {
			int length = results.size();
			long prevBase = Long.MAX_VALUE;
			for(int i = 0; i < length; i++) {
				JSONObject modJson = results.get(length-1 - i);
				String name = modJson.getString("name");
				String path = modJson.getString("path");
				long base = modJson.getBigInteger("base").longValue();
				long size = 0;
				if (modJson.has("size")) {
					size = modJson.getLong("size");
				} else {
					size = prevBase - base;					
				}
				ModuleInfo m = new ModuleInfo(name, path, base, size);
				modules.put(m.getBase(), m);
				modulesByPath.put(m.getPath(), m);
				prevBase = base;
			}
		}
	}
}

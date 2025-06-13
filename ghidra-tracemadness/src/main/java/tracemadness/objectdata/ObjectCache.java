package tracemadness.objectdata;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.json.JSONArray;
import org.json.JSONObject;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureInternal;
import ghidra.util.UniversalID;
import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;
/**
 * This class exists to store all the objects associated with each address for fast lookup by address. 
 * 
 * We need this because if we are going to be translating addresses into object names for every address
 * that happens to show up in the time listing, then we do not want to call out to the database for 
 * each address, but rather to consult a local cache with reasonably efficient storage of this info.
 * 
 * Based on the hypothesis that each address should, over the course of a trace, be a part of relatively
 * few live objects (compared with the number of objects live at a given time, say), we store for each 
 * address all the objects that are ever live and containing that address, in tick-order.
 */

public class ObjectCache implements MadnessQueryResultListener {

	public MadnessPlugin plugin;

	DataTypeManager datatypeManager;
	private HashMap<String, ObjectInfo> keyToObjectMap;
	private TreeMap<Long, TreeMap<Long, ObjectInfo>> addressToObjectsMap; // addr -> tick -> object
	private ArrayList<ObjectInfo> objects;
	private HashMap<String, HashMap<Long, ObjectWitness>> witnessMap; // module -> offset -> witness
	private ArrayList<ObjectWitness> witnesses;

	public ObjectCache(DataTypeManager dtmgr, MadnessPlugin plugin) {
		this.keyToObjectMap = new HashMap<>();
		this.addressToObjectsMap = new TreeMap<>();
		this.plugin = plugin;
		this.datatypeManager = dtmgr;
	}
	
	public void refresh() {
		this.addressToObjectsMap = new TreeMap<>();
		this.keyToObjectMap = new HashMap<>();
		this.objects = new ArrayList<>();
		try {
			String[] params = new String[] { };
			plugin.runQuery("allobjs", params, this, "objects");
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
		try {
			String[] params = new String[] { };
			plugin.runQuery("allwitnesses", params, this, "witnesses");
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
	}
	public TreeMap<Long, ObjectInfo> getLiveObjects(Long tick) {
		TreeMap<Long, ObjectInfo> live = new TreeMap<>();
		for(var obj : objects) {
			if(obj.getBirth() <= tick && (obj.getDeath() == null || obj.getDeath() >= tick) ) {
				live.put(obj.getBase(), obj);
			}
		}
		return live;
	}

	public ObjectInfo getObjectContaining(Long addr, Long tick) {
		TreeMap<Long, ObjectInfo> live = getLiveObjects(tick);
		Long base = live.floorKey(addr);
		if(base == null) return null;
		ObjectInfo obj = live.get(base);
		if(base + obj.getSize() > addr) {
			return obj;
		}
		return null;
	}
	public ObjectInfo getObjectAt(Long addr, Long tick) {
		if(!this.addressToObjectsMap.containsKey(addr)) return null;
		if(!this.addressToObjectsMap.get(addr).containsKey(tick)) return null;
		return this.addressToObjectsMap.get(addr).get(tick);
	}

	public ArrayList<ObjectInfo> getObjects() {
		return this.objects;
	}

	public ObjectWitness getWitness(String module, long offset) {
		if(!this.witnessMap.containsKey(module)) return null;
		HashMap<Long, ObjectWitness> moduleWitnesses = this.witnessMap.get(module);
		if(!moduleWitnesses.containsKey(offset)) return null;
		return moduleWitnesses.get(offset);
	}

	public ArrayList<ObjectWitness> getWitnesses() {
		return this.witnesses;
	}

	public ObjectInfo getObjectByKey(String key) {
		if(this.keyToObjectMap.containsKey(key)) {
			return this.keyToObjectMap.get(key);
		}
		return null;
	}
	private String getTypePath(DataType ty, int offset, int size, boolean hasPrefix) {
		if(ty instanceof Structure) {
			Structure st = (Structure) ty;
			DataTypeComponent component = st.getComponentContaining(offset);
			if(component == null || component.getDataType() == null || component.getDataType().isNotYetDefined()) {
				return String.format("unknown_0x%x_%d", offset, size);
			}
			DataType subtype = component.getDataType();
			String ans = component.getFieldName();
			if(subtype == null || ans == null) {
				ans = String.format("[%d:%d]", offset, offset+size);
				if(hasPrefix) ans = "."+ans;
				return ans;
			}
			String subpath = getTypePath(subtype, offset-component.getOffset(), size, true);
			if(hasPrefix) ans = "."+ans;
			return ans + (subpath != null ? "." + subpath : "");
		} else if(ty instanceof Array) {
			Array ar = (Array)ty;
			int elen = ar.getElementLength();
			DataType etype = ar.getDataType();
			
			String subpath = getTypePath(etype, offset%elen, size, true);
			return String.format("%s[%d]", hasPrefix ? "" : "this", offset/elen) + (subpath != null ? "."+subpath : "");
		} else if(offset == 0 && size == ty.getLength()) {
			return null;
		}
		return (hasPrefix ? "." : "") + "<invalid>";
	}
	
	public String getName(Long addr, long tick, int size) {
		if(this.addressToObjectsMap.containsKey(addr)) {
			TreeMap<Long, ObjectInfo> objsAt = this.addressToObjectsMap.get(addr);
			Map.Entry<Long, ObjectInfo> entry = objsAt.floorEntry(tick);
			if(entry != null && (entry.getValue().getDeath() == null || entry.getValue().getDeath() >= tick)) {
				ObjectInfo obj = entry.getValue();
				DataType t = obj.getType();
				String ans = obj.getName();
				if(t != null) {
					String subpath = getTypePath(t, (int)(addr-obj.getBase()), size, true);
					if(subpath == null) return ans;
					return ans + subpath;
				}
				return ans;
			}
		}
		return null;
	}

	@Override
	public void queryCompleted(List<JSONObject> results, String tag) {
		if(tag.equals("objects")) {
			for (JSONObject ob : results) {
				try {
					String key = ob.getString("_key");
					String name = ob.getString("name");
					long base = ob.getLong("base");
					long birth = ob.getLong("birth");
					Long death = null;
					if(!ob.isNull("death")) death = ob.getLong("death");
					long size = ob.getLong("size");
					String typeId = ob.getString("type");
					UniversalID typeUID = new UniversalID(Long.parseLong(typeId));
					DataType ty = datatypeManager.findDataTypeForID(typeUID);
					ObjectInfo info = new ObjectInfo(key, name, size, base, birth, death, ty);
					this.objects.add(info);
					this.keyToObjectMap.put(info.getKey(), info);
					for(int i = 0; i < size; i++) {
						long addr = base + i;
						if(!this.addressToObjectsMap.containsKey(addr)) {
							this.addressToObjectsMap.put(addr, new TreeMap<>());
						}
						TreeMap<Long, ObjectInfo> objsAt = this.addressToObjectsMap.get(addr);
						objsAt.put(birth, info);
					}
					if(plugin.objectManagerProvider != null) {
						plugin.objectManagerProvider.model.reload();
					}
					
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		} else if(tag.equals("witnesses")) {
			this.witnesses = new ArrayList<>();
			this.witnessMap = new HashMap<>();
			for (JSONObject ob : results) {
				try {
					ObjectWitness w = new ObjectWitness(ob, datatypeManager);
					this.witnesses.add(w);
					if(!this.witnessMap.containsKey(w.moduleName)) this.witnessMap.put(w.moduleName, new HashMap<>());
					this.witnessMap.get(w.moduleName).put(w.offset, w);
				} catch(Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
}

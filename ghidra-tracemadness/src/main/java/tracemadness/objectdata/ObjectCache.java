package tracemadness.objectdata;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.json.JSONArray;
import org.json.JSONObject;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
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
	private TreeMap<Long, TreeMap<Long, ObjectInfo>> addressToObjectsMap;
	private ArrayList<ObjectInfo> objects;

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
	}
	
	public ArrayList<ObjectInfo> getObjects() {
		return this.objects;
	}

	public ObjectInfo getObjectByKey(String key) {
		if(this.keyToObjectMap.containsKey(key)) {
			return this.keyToObjectMap.get(key);
		}
		return null;
	}
	
	private String getTypePath(StructureInternal st, int offset, int size) {
		DataTypeComponent component = st.getComponentContaining(offset);
		if(component == null) {
			return String.format("field_0x%x", offset);
		}
		DataType subtype = component.getDataType();
		String ans = component.getFieldName();
		if(subtype == null || ans == null) {
			ans = String.format("[%d:%d]", offset, offset+size);
		}
		if(subtype instanceof StructureInternal) {
			return ans + "." + getTypePath((StructureInternal)subtype, offset-component.getOffset(), size);
		} else if(offset != component.getOffset()) {
			int off = offset - component.getOffset();
			ans += String.format("[%d:%d]", off, off+size);
		}
		return ans;
	}
	
	public String getName(Long addr, long tick, int size) {
		if(this.addressToObjectsMap.containsKey(addr)) {
			TreeMap<Long, ObjectInfo> objsAt = this.addressToObjectsMap.get(addr);
			Map.Entry<Long, ObjectInfo> entry = objsAt.floorEntry(tick);
			if(entry != null && entry.getValue().getDeath() >= tick) {
				ObjectInfo obj = entry.getValue();
				DataType t = obj.getType(tick);
				String ans = obj.getName();
				if(t != null && t instanceof StructureInternal) {
					return ans + "." + getTypePath((StructureInternal) t, (int)(addr-obj.getBase()), size);
				}
				return ans;
			}
		}
		return null;
	}

	@Override
	public void queryCompleted(List<JSONObject> results, String tag) {
		for (JSONObject ob : results) {
			try {
				String key = ob.getString("_key");
				String name = ob.getString("name");
				long base = ob.getLong("base");
				long birth = ob.getLong("start");
				long death = ob.getLong("end");
				long size = ob.getLong("size");
				JSONArray timeline = ob.getJSONArray("timeline");
				ObjectPhase[] tl = new ObjectPhase[timeline.length()];
				for(int i = 0; i < timeline.length(); i++) {
					JSONObject tlo = timeline.getJSONObject(i);
					long typeId = Long.parseLong(tlo.getString("type"));
					DataType ty = datatypeManager.findDataTypeForID(new UniversalID(typeId));
					ObjectPhase info = new ObjectPhase(tlo.getLong("start"), ty);
					tl[i] = info;
				}
				ObjectInfo info = new ObjectInfo(key, name, size, base, birth, death, tl);
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
				
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}

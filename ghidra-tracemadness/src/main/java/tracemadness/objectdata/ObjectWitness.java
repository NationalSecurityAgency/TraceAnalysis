package tracemadness.objectdata;

import org.json.JSONObject;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.UniversalID;

public class ObjectWitness {

	public enum eventType {BIRTH, CHANGE, DEATH}
	public enum insFeature {REG_WRITE, LOAD_VAL, LOAD_ADDR, STORE_VAL, STORE_ADDR}
	
	public long objOffset;
	public eventType type;
	public insFeature feature;
	public Integer regNum; // for REG_WRITE register 
	public DataType newDataType; // on birth or change
	public String moduleName;
	public Long offset;

	public ObjectWitness(String description, DataTypeManager mgr) {
		JSONObject obj = new JSONObject(description);
		this.type = eventType.valueOf(obj.getString("eventType"));
		if(this.type == eventType.BIRTH || this.type == eventType.DEATH ) {
			UniversalID uid = new UniversalID(Long.parseLong(obj.getString("typeId")));
			this.newDataType = mgr.findDataTypeForID(uid);
		} else {
			this.newDataType = null;
		}
		this.feature = insFeature.valueOf(obj.getString("insFeature"));
		if(this.feature == insFeature.REG_WRITE) {
			this.regNum = obj.getInt("regNum");
		} else {
			this.regNum = null;
		}
		this.moduleName = obj.getString("moduleName");
		this.offset = obj.getLong("moduleOffset");
		if(obj.isNull("objectOffset")) this.objOffset = 0L;
		else this.objOffset = obj.getLong("objectOffset");
	}
	public ObjectWitness(JSONObject obj, DataTypeManager mgr) {
		this.type = eventType.valueOf(obj.getString("eventType"));
		if(this.type == eventType.BIRTH || this.type == eventType.CHANGE ) {
			UniversalID uid = new UniversalID(Long.parseLong(obj.getString("typeId")));
			this.newDataType = mgr.findDataTypeForID(uid);
		} else {
			this.newDataType = null;
		}
		this.feature = insFeature.valueOf(obj.getString("insFeature"));
		if(this.feature == insFeature.REG_WRITE) {
			this.regNum = obj.getInt("regNum");
		} else {
			this.regNum = null;
		}
		this.moduleName = obj.getString("moduleName");
		this.offset = obj.getLong("moduleOffset");
		if(obj.isNull("objectOffset")) this.objOffset = 0L;
		else this.objOffset = obj.getLong("objectOffset");
	}
	public ObjectWitness(eventType type, long objOffset, insFeature feature, Integer reg, DataType newType, String module, Long offset) {
		this.type = type;
		this.feature = feature;
		this.regNum = reg;
		this.newDataType = newType;
		this.moduleName = module;
		this.offset = offset;
		this.objOffset = objOffset;
	}
	public JSONObject toJSON() {
		JSONObject ans = new JSONObject();
		ans.put("eventType",type.toString());
		if(this.type == eventType.BIRTH || this.type == eventType.CHANGE) {
			ans.put("typeId",this.newDataType.getUniversalID().toString());
		}
		ans.put("insFeature", feature.toString());
		if(feature == insFeature.REG_WRITE) {
			ans.put("regNum", regNum);
		}
		ans.put("moduleName", this.moduleName);
		ans.put("moduleOffset", this.offset);
		ans.put("objectOffset", this.objOffset);
		return ans;
	}
	public String getKey() {
		String name = moduleName.replace('/', '_');
		return String.format("%s_%d", name, this.offset);
	}
	public String getFeature() {
		switch(this.feature) {
		case insFeature.REG_WRITE:
			return String.format("register_write(%d)", regNum);
		case insFeature.LOAD_VAL:
			return "memory value read";
		case insFeature.LOAD_ADDR:
			return "memory address read";
		case insFeature.STORE_VAL:
			return "memory value written";
		case insFeature.STORE_ADDR:
			return "memory address written";
		}
		return "";
	}
	public String getEvent() {
		switch(this.type) {
		case eventType.BIRTH:
			return String.format("birth of object of type %s", this.newDataType.getName());
		case eventType.CHANGE:
			return String.format("type change to %s", this.newDataType.getName());
		case eventType.DEATH:
			return "object death";
		}
		return "";
	}
	public String toString() {
		return String.format("%s (offset 0x%x) @ %s:0x%x %s", this.getEvent(), this.objOffset, moduleName, offset, this.getFeature());
	}
}

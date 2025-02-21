package tracemadness.dataflowinfo;

import java.util.ArrayList;

import org.json.JSONObject;

public class DataflowObject {
	
	public long startTick;
	public long endTick;
	public long startAddr;
	public long endAddr;
	public long type;
	public String name;
	public ArrayList<Long> accessTicks;
	
	public DataflowObject(JSONObject src) {
		this.startTick = src.getBigInteger("starttick").longValue();
		this.endTick = src.getBigInteger("endtick").longValue();
		this.startAddr= src.getBigInteger("startaddr").longValue();
		this.endAddr = src.getBigInteger("endaddr").longValue();
		this.type = src.getBigInteger("type").longValue();
		this.name = src.getString("name");
		this.accessTicks = new ArrayList<>();
	}
	
	public void addAccessTick(Long t) {
		this.accessTicks.add(t);
	}
	
	public String toString() {
		return this.name;
	}
}

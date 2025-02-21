package tracemadness.dataflowinfo;

import java.util.ArrayList;

import org.json.JSONArray;
import org.json.JSONObject;

public class DataflowSpaceWithValueRange extends DataflowSpace {
	public Long reads;
	public Long writes;
	public Long minval;
	public Long maxval;
	public Long size;
	public ArrayList<DataflowSpaceOperation> operations;
	public DataflowSpaceWithValueRange(JSONObject row) throws Exception {
		addr = row.getBigInteger("addr").longValue();
		reads = row.getLong("reads");
		writes = row.getLong("writes");
		size = row.getLong("size");
		minval = row.getBigInteger("minval").longValue();
		maxval = row.getBigInteger("maxval").longValue();
		operations = new ArrayList<>();
		JSONArray opsJSON = row.getJSONArray("ops"); 
		for(int i = 0; i < opsJSON.length(); i++) {
			JSONObject obj = opsJSON.getJSONObject(i);
			DataflowSpaceOperation op = new DataflowSpaceOperation(obj.getLong("index"), obj.getBigInteger("val"), obj.getLong("size"), obj.getLong("tick"), obj.getBoolean("is_write"));
			operations.add(op);
		}
	}
	public ArrayList<DataflowSpaceByte> toBytes() {
		ArrayList<DataflowSpaceByte> bytes = new ArrayList<>();
		for(DataflowSpaceOperation op : operations) {
			for(int i = 0; i < size; i++) {
				DataflowSpaceByte b = new DataflowSpaceByte(this.addr + i, this.addr, this.reads, this.writes, this.operations);
				bytes.add(b);
			}
		}
		return bytes;
	}
}

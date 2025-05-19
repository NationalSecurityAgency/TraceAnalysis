package tracemadness.memindex;

import java.util.ArrayList;

import org.json.JSONArray;
import org.json.JSONObject;

import tracemadness.dataflowinfo.DataflowSpaceMemoryByte;

public class MemoryValueQueryResult {
	public ArrayList<DataflowSpaceMemoryByte> bytes;
	public MemoryValueQueryResult(JSONObject obj) {
		JSONArray vals = obj.getJSONArray("mem_results");
		JSONArray addrs = obj.getJSONArray("mem_addrs");
		JSONArray times = obj.getJSONArray("mem_ticks");
		this.bytes = new ArrayList<>();
		for(int i = 0; i < addrs.length(); i++) {
			if(times.getLong(i) == 0) continue;
			this.bytes.add(new DataflowSpaceMemoryByte(addrs.getBigInteger(i).longValue(), (byte)(vals.getInt(i)),times.getLong(i)));
		}
	}
	public String toString() {
		String ans = "";
		for(int i = 0; i < bytes.size(); i++) {
			ans += String.format("[0x%x] = 0x%02x since %d\n", bytes.get(i).addr, bytes.get(i).value, bytes.get(i).tick);
		}
		return ans;
	}
}
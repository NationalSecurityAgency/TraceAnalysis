package tracemadness.slicelisting;

import java.math.BigInteger;

import org.json.JSONArray;
import org.json.JSONObject;

public class SliceItem {

	public Long index;
	public Long tick;
	public Long[] path;
	public String disas;
	public String reg;
	public Long addr;
	public Long pc;
	public BigInteger value;
	public int size;

	public SliceItem(JSONObject src) {
		this.index = src.getLong("index");
		this.tick = src.getLong("tick");
		JSONArray p = src.getJSONArray("path");
		this.path = new Long[p.length()];
		for(int i = 0; i < p.length(); i++) {
			this.path[i] = p.getLong(i);
		}
		this.disas = src.getString("disas");
		this.reg = src.getString("reg");
		this.addr = src.getLong("addr");
		this.pc = src.getLong("pc");
		String val;
		try {
			val = src.getString("value");
		} catch(org.json.JSONException exc) {
			val = Long.toString(src.getLong("value"));
		}
		this.value = new BigInteger(val, 16);
		this.size = src.getInt("size");
	}
}

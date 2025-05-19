package tracemadness.memindex;

import java.math.BigInteger;
import java.util.ArrayList;

import org.json.JSONArray;
import org.json.JSONObject;

public class MemorySearchResult {
	public ArrayList<Long> createticks;
	public ArrayList<Long> destroyticks;
	public ArrayList<BigInteger> addresses;
	public MemorySearchResult(JSONObject obj) {
		this.createticks = new ArrayList<>();
		this.destroyticks = new ArrayList<>();
		this.addresses = new ArrayList<>();
		JSONArray creations = obj.getJSONArray("buffer_creation_ticks");
		JSONArray destructions = obj.getJSONArray("buffer_destruction_ticks");
		JSONArray addrs = obj.getJSONArray("buffer_addrs");
		for(int i = 0; i < creations.length(); i++) {
			this.createticks.add(creations.getLong(i));
		}
		for(int i = 0; i < destructions.length(); i++) {
			this.destroyticks.add(destructions.getLong(i));
		}
		for(int i = 0; i < addrs.length(); i++) {
			this.addresses.add(addrs.getBigInteger(i));
		}
	}
	public String toString() {
		String ans = "";
		for(int i = 0; i < addresses.size(); i++) {
			ans += String.format("target @ 0x%s %d-%d\n", addresses.get(i).toString(16), createticks.get(i), destroyticks.get(i));
		}
		return ans;
	}
}

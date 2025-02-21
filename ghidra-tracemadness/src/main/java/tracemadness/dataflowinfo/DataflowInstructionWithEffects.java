package tracemadness.dataflowinfo;

import java.math.BigInteger;
import java.util.ArrayList;

import org.json.JSONArray;
import org.json.JSONObject;

import tracemadness.MadnessPlugin;

public class DataflowInstructionWithEffects extends DataflowTime {
	
	public long pc;
	public String disas;
	public ArrayList<DataflowEffect> effects;
	public DataflowFunctionWithArgs function;
	public DataflowInstructionWithEffects(JSONObject src, MadnessPlugin plugin) throws Exception {
		this.type = INSTRUCTIONRUN;
		this.function = null;
		tick = src.getLong("tick");
		pc = src.getLong("pc");
		disas = src.getString("disassembly");
		effects = new ArrayList<DataflowEffect>();
		
		if (!src.isNull("regwrites")) {
			JSONArray arr = src.getJSONArray("regwrites");
			for(int i = 0; i < arr.length(); i++) {
				JSONObject x = arr.getJSONObject(i);
				if(!x.has("index") || !x.has("name") || !x.has("val")) continue;
				if(x.isNull("index") || x.isNull("name") || x.isNull("val")) continue;
				Long index = x.getLong("index");
				Long size = x.getLong("size");
				String name = x.getString("name");
				BigInteger val = null;
				if(x.has("raw") && !x.isNull("raw")) val = x.get("raw") instanceof String ? new BigInteger(x.getString("raw"), 16) : x.getBigInteger("raw");

				// add to effects
				effects.add(new DataflowEffect(DataflowEffect.DataflowEffectType.REG_WRITE, index, val, size, name, null, true));
			}
		}
		if (!src.isNull("memreads")) {
			JSONArray arr = src.getJSONArray("memreads");
			for(int i = 0; i < arr.length(); i++) {
				JSONObject x = arr.getJSONObject(i);
				if(!x.has("index") || !x.has("src") || !x.has("size")) continue;
				if(x.isNull("index") || x.isNull("src") || x.isNull("size")) continue;
				Long index = x.getLong("index");
				Long srcAddr = x.getLong("src");
				BigInteger val = null;
				if(x.has("raw") && !x.isNull("raw")) val = x.get("raw") instanceof String ? new BigInteger(x.getString("raw"), 16) : x.getBigInteger("raw");
				Long size = x.getLong("size");
				effects.add(new DataflowEffect(DataflowEffect.DataflowEffectType.MEM_READ, index, val, size, null, srcAddr, false));
			}
		}
		if (!src.isNull("memwrites")) {
			JSONArray arr = src.getJSONArray("memwrites");
			for(int i = 0; i < arr.length(); i++) {
				JSONObject x = arr.getJSONObject(i);
				if(!x.has("index") || !x.has("dest") || !x.has("val") || !x.has("size")) continue;
				if(x.isNull("index") || x.isNull("dest") || x.isNull("val") || x.isNull("size")) continue;
				Long index = x.getLong("index");
				Long destAddr = x.getBigInteger("dest").longValue();
				BigInteger val = null;
				if(x.has("raw") && !x.isNull("raw")) val = x.get("raw") instanceof String ? new BigInteger(x.getString("raw"), 16) : x.getBigInteger("raw");
				Long size = x.getLong("size");
				effects.add(new DataflowEffect(DataflowEffect.DataflowEffectType.MEM_WRITE, index, val, size, null, destAddr, true));
			}
		}
		if (!src.isNull("memaddrs")) {
			JSONArray arr = src.getJSONArray("memaddrs");
			for(int i = 0; i < arr.length(); i++) {
				JSONObject x = arr.getJSONObject(i);
				if(!x.has("index") || !x.has("val") || !x.has("size")) continue;
				if(x.isNull("index") || x.isNull("val") || x.isNull("size")) continue;
				Long index = x.getLong("index");
				BigInteger val = null;
				if(x.has("raw") && !x.isNull("raw")) val = x.get("raw") instanceof String ? new BigInteger(x.getString("raw"), 16) : x.getBigInteger("raw");
				Long size = x.getLong("size");
				effects.add(new DataflowEffect(DataflowEffect.DataflowEffectType.MEM_ACCESS, index, val, size, null, null, null));
			}
		}
		if (!src.isNull("fncalls") ) {
			JSONArray fns = src.getJSONArray("fncalls");
			if(fns.length() == 1) {
				this.function = new DataflowFunctionWithArgs(fns.getJSONObject(0), plugin);
			}
		}
	}
}

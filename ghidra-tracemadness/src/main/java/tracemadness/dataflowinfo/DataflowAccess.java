package tracemadness.dataflowinfo;

import java.math.BigInteger;

import org.json.JSONObject;

public class DataflowAccess {
	
	public long index;
	public long tick;
	public BigInteger val;
	public long size;
	public String destStr;
	public Long addr; 
	public Boolean isWrite;
	public String name;
	public String disas;
	public String pcDescription;
	public Long pc;
	
	public DataflowAccess(JSONObject src) {
		this.index = src.getBigInteger("index").longValue();
		this.tick = src.getBigInteger("tick").longValue();
		this.val = src.getBigInteger("val");
		this.size = src.getLong("size");
		this.addr = src.getLong("addr");
		this.pc = src.getLong("pc");
		this.disas = src.getString("disas");
		this.isWrite = src.getBoolean("is_write");
		this.name = "";
		this.pcDescription = "";
	}
	
	public DataflowAccess(long index, long tick, BigInteger val, long size, String destStr, Long addr, Boolean isWrite, Long pc, String disas, String pcDesc, String name) {
		this.index = index;
		this.tick = tick;
		this.val = val;
		this.size = size;
		this.destStr = destStr;
		this.addr = addr;
		this.isWrite = isWrite;
		this.pc = pc;
		this.pcDescription = pcDesc;
		this.name = name;
		this.disas = disas;
	}
	
	public String toString() {
		String direction = this.isWrite  ? "<-" : "->";
		return String.format("[0x%x]:%d %s 0x%s at PC=0x%x T=%d", this.addr, this.size, direction, this.val.toString(16), this.pc, this.tick);
	}
	
	public String valStr() {
		if(this.val == null) {
			return "?";
		}
		return this.valStr().toString();
	}
}

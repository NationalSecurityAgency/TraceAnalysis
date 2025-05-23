package tracemadness.accesslisting;

import org.json.JSONObject;

public class AccessEvent {

	private long tick, addr, pc, index;
	private byte[] val;
	private int size;
	private boolean write;

	public AccessEvent(JSONObject obj) {
		this.index = obj.getLong("index");
		this.tick = obj.getLong("tick");
		this.addr = obj.getLong("addr");
		this.size = (int)obj.getLong("size");
		String val_str = obj.getString("raw");
		if(val_str.length() % 2 != 0) {
			val_str = "0"+val_str;
		}
		this.val = new byte[val_str.length()/2];
		for(int i = 0; i < val_str.length(); i += 2) {
			val[i/2] = (byte)Integer.parseInt(val_str.substring(i,i+2),16);
		}
		
		this.pc = obj.getLong("pc");
		this.write = obj.getBoolean("is_write");
	}
	public AccessEvent(long index, long tick, long addr, int size, byte[] val, long pc, boolean write) {
		this.index = index;
		this.tick = tick;
		this.addr = addr;
		this.size = size;
		this.val = val;
		this.pc = pc;
		this.write = write;
	}
	
	public long getIndex() {
		return this.index;
	}
	public long getTick() {
		return this.tick;
	}
	public long getAddr() {
		return this.addr;
	}
	public long getPC() {
		return this.pc;
	}
	public byte[] getVal() {
		return this.val;
	}
	public int getSize() {
		return this.size;
	}
	public boolean isWrite() {
		return write;
	}
}

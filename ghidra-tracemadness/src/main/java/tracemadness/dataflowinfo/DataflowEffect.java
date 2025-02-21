package tracemadness.dataflowinfo;

import java.math.BigInteger;

public class DataflowEffect {
	
	public static enum DataflowEffectType {
		REG_WRITE, MEM_READ, MEM_WRITE, MEM_ACCESS, BRANCH
	}
	
	public DataflowEffectType type;
	public long index;
	public BigInteger val;
	public long size;
	public String destStr;
	public Long addr; 
	public Boolean isWrite;
	
	public DataflowEffect(DataflowEffectType ty, long index, BigInteger val, long size, String destStr, Long addr, Boolean isWrite) {
		this.type = ty;
		this.index = index;
		this.val = val;
		this.size = size;
		this.destStr = destStr;
		this.addr = addr;
		this.isWrite = isWrite;
	}
	
	public String valStr() {
		if(this.val == null) {
			return "?";
		}
		return this.valStr().toString();
	}
}

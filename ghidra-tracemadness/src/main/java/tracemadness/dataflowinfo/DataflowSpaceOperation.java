package tracemadness.dataflowinfo;

import java.math.BigInteger;

public class DataflowSpaceOperation {
	
	public Long index;
	public BigInteger val;
	public Long tick;
	public Long size;
	public boolean is_write;
	
	public DataflowSpaceOperation(Long index, BigInteger val, Long size, Long tick, boolean is_write) {
		this.index = index;
		this.val = val;
		this.size = size;
		this.tick = tick;
		this.is_write = is_write;
	}
}

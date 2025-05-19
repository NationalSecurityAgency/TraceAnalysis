package tracemadness.dataflowinfo;

import java.math.BigInteger;
import java.util.ArrayList;


public class DataflowSpaceMemoryByte extends DataflowSpace {
	public long tick;
	public byte value;
	public DataflowSpaceMemoryByte(Long addr, byte value, Long tick) {
		this.addr = addr;
		this.tick = tick;
		this.value = value;
	}
}

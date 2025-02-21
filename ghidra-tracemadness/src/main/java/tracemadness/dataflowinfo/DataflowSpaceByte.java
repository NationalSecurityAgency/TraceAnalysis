package tracemadness.dataflowinfo;

import java.math.BigInteger;
import java.util.ArrayList;


public class DataflowSpaceByte extends DataflowSpace {
	public Long addr;
	public Long reads;
	public Long writes;
	public Long minval;
	public Long maxval;
	public Long size;
	public ArrayList<DataflowSpaceOperation> operations;
	public DataflowSpaceByte(Long addr, Long baseaddr, long reads, long writes, ArrayList<DataflowSpaceOperation> ops) {
		this.addr = addr;
		this.reads = reads;
		this.writes = writes;
		operations = new ArrayList<>(); 
		for(int i = 0; i < ops.size(); i++) {
			long offset = addr - baseaddr;
			DataflowSpaceOperation fullop = ops.get(i);
			DataflowSpaceOperation op = new DataflowSpaceOperation(fullop.index, 
					fullop.val.shiftRight((int)offset*8).and(new BigInteger(new byte[] {(byte) 0xff})), 
					1L,
					fullop.tick, 
					fullop.is_write);
			operations.add(op);
		}
	}
}

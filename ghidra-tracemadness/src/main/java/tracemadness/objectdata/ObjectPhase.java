package tracemadness.objectdata;

import ghidra.program.model.data.DataType;

public class ObjectPhase {

	private Long start;
	private DataType ty;

	public ObjectPhase(Long start, DataType ty) {
		this.start = start;
		this.ty = ty;
	}
	
	public Long getStart() {
		return this.start;
	}

	public void setStart(Long start) {
		this.start = start;
	}

	public DataType getType() {
		return this.ty;
	}
	public void setType(DataType ty) {
		this.ty = ty;
	}
}

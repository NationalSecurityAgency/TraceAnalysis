package tracemadness.accesslisting;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import tracemadness.objectdata.ObjectInfo;

public class AnnotatedAccessEvent {
	public AccessEvent event;
	public ObjectInfo obj;
	public Function func;
	
	public AnnotatedAccessEvent(AccessEvent e, ObjectInfo obj, Function f) {
		this.event = e;
		this.obj = obj;
		this.func = f;
	}
	public boolean hasValidObject() {
		return this.obj != null && this.obj.getType() != null;
	}
	public boolean hasValidField() {
		if(!this.hasValidObject()) return false;
		StructureDataType ty = (StructureDataType)this.obj.getType();
		int offset = (int)(this.event.getAddr() - this.obj.getBase());
		DataTypeComponent c = ty.getComponentContaining(offset);
		if(c != null && c.getOffset() == offset && c.getDataType().getLength() == this.event.getSize()) {
			return true;
		}
		return false;
	}
}

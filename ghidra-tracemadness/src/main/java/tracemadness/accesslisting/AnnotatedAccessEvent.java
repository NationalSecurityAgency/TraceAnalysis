package tracemadness.accesslisting;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
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
		return isValidFieldHelper(this.obj.getType(), (int)(this.event.getAddr()-this.obj.getBase()), this.event.getSize());
	}
	private boolean isValidFieldHelper(DataType ty, int offset, int size) {
		if(ty == null) return false;
		if(ty instanceof Structure) {
			DataTypeComponent c = ((Structure)ty).getComponentContaining(offset);
			if(c == null) return false;
			DataType cType = c.getDataType();
			if(cType == null || cType.isNotYetDefined()) return false;
			return isValidFieldHelper(cType, offset-c.getOffset(), size);
		} else if(ty instanceof Array) {
			DataType etype = ((Array)ty).getDataType();
			int elen = ((Array)ty).getElementLength();
			if(size > elen) return false;
			return isValidFieldHelper(etype, offset % elen, size);
		} else if(offset == 0 && ty.getLength() == size) {
			return true;
		}
		return false;
	}
}

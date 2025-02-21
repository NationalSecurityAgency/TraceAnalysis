package tracemadness.accessmap;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import tracemadness.objectdata.ObjectInfo;

public class AccessMapActionContext extends DefaultActionContext {
	
	private ObjectInfo obj;
	public AccessMapActionContext(ComponentProvider provider, ObjectInfo obj) {
		super(provider);
		this.obj = obj;
	}
	public ObjectInfo getObject() {
		return this.obj;
	}
}

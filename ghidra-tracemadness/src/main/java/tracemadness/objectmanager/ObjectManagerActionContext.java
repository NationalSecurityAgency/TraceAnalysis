package tracemadness.objectmanager;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import tracemadness.objectdata.ObjectInfo;

public class ObjectManagerActionContext extends DefaultActionContext {
	
	private ObjectInfo obj;
	public ObjectManagerActionContext(ComponentProvider provider, ObjectInfo obj) {
		super(provider);
		this.obj = obj;
	}
	public ObjectInfo getObject() {
		return this.obj;
	}
}

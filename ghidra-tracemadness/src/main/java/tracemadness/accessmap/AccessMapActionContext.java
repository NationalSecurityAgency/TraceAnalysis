package tracemadness.accessmap;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import tracemadness.accesslisting.AccessEvent;
import tracemadness.objectdata.ObjectInfo;

public class AccessMapActionContext extends DefaultActionContext {
	
	private AccessEvent event;
	private ObjectInfo obj;
	public AccessMapActionContext(ComponentProvider provider, AccessEvent e, ObjectInfo obj) {
		super(provider);
		this.obj = obj;
		this.event = e;
	}
	public ObjectInfo getObject() {
		return this.obj;
	}
	public AccessEvent getAccess() {
		return this.event;
	}
}

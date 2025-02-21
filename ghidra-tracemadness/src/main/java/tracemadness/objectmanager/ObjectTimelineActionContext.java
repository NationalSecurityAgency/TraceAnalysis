package tracemadness.objectmanager;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.objectdata.ObjectPhase;

public class ObjectTimelineActionContext extends DefaultActionContext {
	
	private ObjectPhase info;
	private ObjectInfo obj;
	public ObjectTimelineActionContext(ComponentProvider provider, ObjectInfo obj, ObjectPhase info) {
		super(provider);
		this.obj = obj;
		this.info = info;
	}
	public ObjectPhase getObjectType() {
		return this.info;
	}
	public ObjectInfo getObject() {
		return this.obj;
	}
}

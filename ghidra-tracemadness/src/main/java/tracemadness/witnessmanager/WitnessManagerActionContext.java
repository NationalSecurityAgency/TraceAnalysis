package tracemadness.witnessmanager;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import tracemadness.objectdata.ObjectWitness;

public class WitnessManagerActionContext extends DefaultActionContext {
	
	private ObjectWitness obj;
	public WitnessManagerActionContext(ComponentProvider provider, ObjectWitness obj) {
		super(provider);
		this.obj = obj;
	}
	public ObjectWitness getObject() {
		return this.obj;
	}
}

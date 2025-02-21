package tracemadness.modulemap;

import docking.ComponentProvider;
import docking.DefaultActionContext;

public class ModuleMapActionContext extends DefaultActionContext {
	
	private ModuleInfo obj;
	public ModuleMapActionContext(ComponentProvider provider, ModuleInfo obj) {
		super(provider);
		this.obj = obj;
	}
	public ModuleInfo getObject() {
		return this.obj;
	}
}

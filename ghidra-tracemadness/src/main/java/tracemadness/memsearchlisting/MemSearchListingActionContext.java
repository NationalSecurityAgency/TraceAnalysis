package tracemadness.memsearchlisting;

import docking.ComponentProvider;
import docking.DefaultActionContext;

public class MemSearchListingActionContext extends DefaultActionContext {
	
	private MemSearchItem obj;
	ComponentProvider provider;
	public MemSearchListingActionContext(ComponentProvider provider, MemSearchItem obj) {
		super(provider);
		this.provider = provider;
		this.obj = obj;
	}
	public MemSearchItem getObject() {
		return this.obj;
	}
}

package tracemadness.slicelisting;

import docking.ComponentProvider;
import docking.DefaultActionContext;

public class SliceListingActionContext extends DefaultActionContext {
	
	private SliceItem obj;
	ComponentProvider provider;
	public SliceListingActionContext(ComponentProvider provider, SliceItem obj) {
		super(provider);
		this.provider = provider;
		this.obj = obj;
	}
	public SliceItem getObject() {
		return this.obj;
	}
}

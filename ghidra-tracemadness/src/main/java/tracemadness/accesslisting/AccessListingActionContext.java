package tracemadness.accesslisting;

import docking.ComponentProvider;
import docking.DefaultActionContext;

public class AccessListingActionContext extends DefaultActionContext {
	
	private AnnotatedAccessEvent obj;
	public AccessListingActionContext(ComponentProvider provider, AnnotatedAccessEvent obj) {
		super(provider);
		this.obj = obj;
	}
	public AnnotatedAccessEvent getObject() {
		return this.obj;
	}
}

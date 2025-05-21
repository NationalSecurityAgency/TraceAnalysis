package tracemadness.newaccesslisting;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import docking.widgets.fieldpanel.field.Field;

public class AccessListingActionContext extends DefaultActionContext {
	
	private Field field;
	public AccessListingActionContext(ComponentProvider provider, Field f) {
		super(provider);
		this.field = f;
	}
	public Field getField() {
		return this.field;
	}
}

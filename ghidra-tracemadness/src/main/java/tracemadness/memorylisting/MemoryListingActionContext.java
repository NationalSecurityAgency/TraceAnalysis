package tracemadness.memorylisting;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import docking.widgets.fieldpanel.field.Field;

public class MemoryListingActionContext extends DefaultActionContext {
	
	private Field field;
	public MemoryListingActionContext(ComponentProvider provider, Field f) {
		super(provider);
		this.field = f;
	}
	public Field getField() {
		return this.field;
	}
}

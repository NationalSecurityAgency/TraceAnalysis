package tracemadness.spacelisting;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import docking.widgets.fieldpanel.field.Field;

public class SpaceListingActionContext extends DefaultActionContext {
	
	private Field field;
	public SpaceListingActionContext(ComponentProvider provider, Field f) {
		super(provider);
		this.field = f;
	}
	public Field getField() {
		return this.field;
	}
}

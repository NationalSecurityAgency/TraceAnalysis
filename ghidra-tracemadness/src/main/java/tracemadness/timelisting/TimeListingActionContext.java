package tracemadness.timelisting;

import java.math.BigInteger;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import docking.widgets.fieldpanel.field.Field;

public class TimeListingActionContext extends DefaultActionContext {
	
	private Field field;
	private BigInteger index;
	public TimeListingActionContext(ComponentProvider provider, Field f, BigInteger idx) {
		super(provider);
		this.field = f;
		this.index = idx;
	}
	public Field getField() {
		return this.field;
	}
	public BigInteger getIndex() {
		return this.index;
	}
}

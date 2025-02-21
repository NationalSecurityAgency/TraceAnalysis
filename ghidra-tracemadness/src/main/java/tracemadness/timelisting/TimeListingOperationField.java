package tracemadness.timelisting;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import tracemadness.listingfield.SpacetimeOperationField;
import tracemadness.listingfield.SpacetimePCField;
import tracemadness.listingfield.SpacetimeTickField;

import java.awt.FontMetrics;
import java.math.BigInteger;

public class TimeListingOperationField extends ClippingTextField implements SpacetimeOperationField, SpacetimeTickField, SpacetimePCField {

	private long index; // the index (database primary key) of the operation
	private long tick; // the tick of the instruction of which this operation is a part
	private long pc; // the pc of the instruction of which this operation is a part
	private BigInteger value; // the value written
	private Long dest; // The destination address (if any)
	private Boolean is_write;
	private String display;
	private String description;
	public TimeListingOperationField(long index, Long dest, BigInteger value, long tick, long pc, Boolean is_write, String display, String longdesc, int startX, int width, FontMetrics fm, FieldHighlightFactory hlFactory) {
		super(startX, width, new TextFieldElement(new AttributedString(display, TimeListingSettings.OP_COLOR, fm), 0, 0), hlFactory);
		this.index = index;
		this.value = value;
		this.tick = tick;
		this.pc = pc;
		this.is_write = is_write;
		this.dest = dest;
		this.display = display;
		this.description = longdesc;
	}
	public long getIndex() {
		return index;
	}
	public long getTick() {
		return tick;
	}
	public boolean isWrite() {
		return is_write;
	}
	public long getPC() {
		return this.pc;
	}
	public Long getDest() {
		return this.dest;
	}
	public BigInteger getValue() {
		return this.value;
	}
	public String getDisplay() {
		return this.display;
	}
	@Override
	public String getDescription() {
		return this.description;
	}
}

package tracemadness.timelisting;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import tracemadness.listingfield.SpacetimePCField;
import tracemadness.listingfield.SpacetimeTickField;

import java.awt.FontMetrics;

public class TimeListingPCField extends ClippingTextField implements SpacetimeTickField, SpacetimePCField {

	private long tick;
	private long pc;
	public TimeListingPCField(long tick, long pc, int startX, int width, FontMetrics fm, FieldHighlightFactory hlFactory) {
		super(startX, width, new TextFieldElement(new AttributedString(String.format("0x%x", pc), TimeListingSettings.PC_COLOR, fm), 0, 0), hlFactory);
		this.tick = tick;
		this.pc = pc;
	}
	public long getPC() {
		return this.pc;
	}
	public long getTick() {
		return this.tick;
	}
}

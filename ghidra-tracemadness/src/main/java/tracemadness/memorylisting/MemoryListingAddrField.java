package tracemadness.memorylisting;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import tracemadness.listingfield.SpacetimeTickField;
import tracemadness.listingfield.SpacetimeAddrField;
import tracemadness.timelisting.TimeListingSettings;

import java.awt.FontMetrics;

public class MemoryListingAddrField extends ClippingTextField implements SpacetimeAddrField, SpacetimeTickField {

	private long addr;
	private long tick;
	public MemoryListingAddrField(long addr, long tick, String desc, int startX, int width, FontMetrics fm, FieldHighlightFactory hlFactory) {
		super(startX, width, new TextFieldElement(new AttributedString(desc, TimeListingSettings.PC_COLOR, fm), 0, 0), hlFactory);
		this.addr = addr;
		this.tick = tick;
	}
	public long getAddr() {
		return this.addr;
	}
	public long getTick() {
		return this.tick;
	}
}

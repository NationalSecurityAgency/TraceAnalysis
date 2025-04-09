package tracemadness.memorylisting;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import tracemadness.listingfield.SpacetimeAddrField;

import java.awt.FontMetrics;

public class MemoryListingTextField extends ClippingTextField implements SpacetimeAddrField {

	private long addr;
	private boolean is_write;
	public MemoryListingTextField(long addr, boolean is_write, String desc, int startX, int width, FontMetrics fm, FieldHighlightFactory hlFactory) {
		super(startX, width, new TextFieldElement(new AttributedString(desc, MemoryListingSettings.TEXT_COLOR, fm), 0, 0), hlFactory);
		this.addr = addr;
		this.is_write = is_write;
	}
	public long getAddr() {
		return this.addr;
	}
	public boolean isWrite() {
		return this.is_write;
	}
}

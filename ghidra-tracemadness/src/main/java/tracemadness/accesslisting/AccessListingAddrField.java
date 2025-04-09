package tracemadness.accesslisting;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import tracemadness.listingfield.SpacetimeAddrField;
import tracemadness.timelisting.TimeListingSettings;

import java.awt.FontMetrics;

public class AccessListingAddrField extends ClippingTextField implements SpacetimeAddrField {

	private long addr;
	public AccessListingAddrField(long addr, String desc, int startX, int width, FontMetrics fm, FieldHighlightFactory hlFactory) {
		super(startX, width, new TextFieldElement(new AttributedString(desc, TimeListingSettings.PC_COLOR, fm), 0, 0), hlFactory);
		this.addr = addr;
	}
	public long getAddr() {
		return this.addr;
	}
}

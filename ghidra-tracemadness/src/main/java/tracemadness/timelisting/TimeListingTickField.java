package tracemadness.timelisting;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import tracemadness.listingfield.SpacetimeTickField;

import java.awt.FontMetrics;

public class TimeListingTickField extends ClippingTextField implements SpacetimeTickField {

	private long tick;
	public TimeListingTickField(long tick, int startX, int width, FontMetrics fm, FieldHighlightFactory hlFactory) {
		super(startX, width, new TextFieldElement(new AttributedString(Long.toString(tick), TimeListingSettings.TICK_COLOR, fm), 0, 0), hlFactory);
		this.tick = tick;
	}
	public long getTick() {
		return this.tick;
	}
}

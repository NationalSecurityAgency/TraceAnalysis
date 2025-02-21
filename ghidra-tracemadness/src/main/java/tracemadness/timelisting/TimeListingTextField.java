package tracemadness.timelisting;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import tracemadness.listingfield.SpacetimePCField;
import tracemadness.listingfield.SpacetimeTickField;

import java.awt.FontMetrics;

public class TimeListingTextField extends ClippingTextField implements SpacetimeTickField, SpacetimePCField {

	private long tick;
	private long pc;
	private String disas;
	public TimeListingTextField(long tick, long pc, String disas, int startX, int width, FontMetrics fm, FieldHighlightFactory hlFactory) {
		super(startX, width, new TextFieldElement(new AttributedString(disas, TimeListingSettings.DISAS_COLOR, fm), 0, 0), hlFactory);
		this.tick = tick;
		this.pc = pc;
		this.disas = disas;
	}
	public long getTick() {
		return tick;
	}
	public long getPC() {
		return this.pc;
	}
	public String getDisas() {
		return disas;
	}
}

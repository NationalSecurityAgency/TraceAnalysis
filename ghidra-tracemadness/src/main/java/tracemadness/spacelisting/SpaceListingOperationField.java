package tracemadness.spacelisting;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import tracemadness.listingfield.SpacetimeAddrField;
import tracemadness.listingfield.SpacetimeOperationField;
import tracemadness.listingfield.SpacetimeTickField;
import tracemadness.timelisting.TimeListingSettings;

import java.awt.FontMetrics;
import java.math.BigInteger;

public class SpaceListingOperationField extends ClippingTextField implements SpacetimeTickField, SpacetimeOperationField, SpacetimeAddrField {

	private Long addr;
	private Long index;
	private Long tick;
	private BigInteger val;
	private Boolean is_write;
	private String description;
	public SpaceListingOperationField(Long addr, Long index, Long tick, BigInteger val, Boolean is_write, String desc, String longdesc, int startX, int width, FontMetrics fm, FieldHighlightFactory hlFactory) {
		super(startX, width, new TextFieldElement(new AttributedString(desc, TimeListingSettings.PC_COLOR, fm), 0, 0), hlFactory);
		this.addr = addr;
		this.index = index;
		this.tick = tick;
		this.val = val;
		this.is_write = is_write;
		this.description = longdesc;
	}
	public long getAddr() {
		return this.addr;
	}
	@Override
	public boolean isWrite() {
		return this.is_write;
	}
	@Override
	public long getTick() {
		return this.tick;
	}
	@Override
	public long getIndex() {
		return this.index;
	}
	@Override
	public BigInteger getValue() {
		return this.val;
	}
	@Override
	public Long getDest() {
		return this.addr;
	}
	@Override
	public String getDescription() {
		return this.description;
	}
}

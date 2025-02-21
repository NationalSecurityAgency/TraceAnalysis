package tracemadness.listingfield;

import java.math.BigInteger;

public interface SpacetimeOperationField {
	public long getIndex();
	public BigInteger getValue();
	public Long getDest();
	public boolean isWrite();
	public String getDescription();
}

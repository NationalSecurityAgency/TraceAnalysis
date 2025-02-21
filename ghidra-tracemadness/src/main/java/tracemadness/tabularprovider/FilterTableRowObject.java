package tracemadness.tabularprovider;

import ghidra.program.model.address.Address;

public class FilterTableRowObject {

	Integer filterIndex;
	String filterDescription;
	boolean enabled;

	public FilterTableRowObject(Integer filterIndex, String filterDescription, boolean enabled) {
		this.filterIndex = filterIndex;
		this.filterDescription = filterDescription;
		this.enabled = enabled;
	}

	public String getFilterDescription() {
		return filterDescription;
	}

	public void setFilterDescription(String filterDescription) {
		this.filterDescription = filterDescription;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public Integer getIndex() {
		return filterIndex;
	}

	public Address getAddress() {
		return null;
	}

}

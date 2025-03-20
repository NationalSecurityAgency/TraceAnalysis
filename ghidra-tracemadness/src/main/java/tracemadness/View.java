package tracemadness;

public interface View {
	public String toString();

	public String toAQLString();

	public void setViewType(String ty);

	public String[] getViewTypes();

	public String[] getViewParams(String name);

	public String getViewTypeName();

	public Long getViewParam(String name);

	public void setViewParam(String name, Long val);

	public View deepCopy();
}

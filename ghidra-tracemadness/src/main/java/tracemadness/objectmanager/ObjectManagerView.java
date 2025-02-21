package tracemadness.objectmanager;

import java.util.HashMap;
import java.util.Map;

import tracemadness.tabularprovider.View;

public class ObjectManagerView implements View {

	public static enum VIEW_TYPE {
		ALL_VIEW, TIME_WINDOW_VIEW, ADDR_WINDOW_VIEW
	}

	public static enum VIEW_PARAM {
		TIME_START, TIME_END, ADDR_START, ADDR_END
	}

	public VIEW_TYPE viewType;
	public Map<String, Long> viewParams;

	public ObjectManagerView() {
		this.viewType = VIEW_TYPE.ALL_VIEW;
		this.viewParams = new HashMap<String, Long>();
	}

	public ObjectManagerView(String ty, Map<String, Long> params) {
		this.viewType = VIEW_TYPE.valueOf(ty);
		this.viewParams = new HashMap<String, Long>(params);
	}

	public String toString() {
		switch (this.viewType) {
		case ALL_VIEW:
			return String.format("All objects");
		case TIME_WINDOW_VIEW:
			return String.format("All objects accessed between tick %d and %d", this.getViewParam(VIEW_PARAM.TIME_START.name()), this.getViewParam(VIEW_PARAM.TIME_END.name()));
		case ADDR_WINDOW_VIEW:
			return String.format("All objects containing addresses 0x%x and 0x%x", this.getViewParam(VIEW_PARAM.ADDR_START.name()), this.getViewParam(VIEW_PARAM.ADDR_END.name()));
		}
		return "";
	}

	public String toAQLString() {
		switch (this.viewType) {
		case ALL_VIEW:
			return String.format("for obj in objects \n");
		case TIME_WINDOW_VIEW:
			return String.format("let starttick=%d\n"
					+ "let endtick=%d\n"
					+ "for obj in objects \n"
					+ "filter starttick <= obj.endtick and obj.start <= endtick\n", 
					this.getViewParam(VIEW_PARAM.TIME_START.name()), this.getViewParam(VIEW_PARAM.TIME_END.name()));
		case ADDR_WINDOW_VIEW:
			return String.format("let startaddr=%d\n"
					+ "let endaddr=%d\n"
					+ "for obj in objects \n"
					+ "filter startaddr <= obj.base+obj.size and obj.base <= endaddr\n", 
					this.getViewParam(VIEW_PARAM.ADDR_START.name()), this.getViewParam(VIEW_PARAM.ADDR_END.name()));
			}
		return "";
	}

	@Override
	public void setViewType(String ty) {
		this.viewType = VIEW_TYPE.valueOf(ty);
	}

	@Override
	public String[] getViewTypes() {
		return new String[] { 
				VIEW_TYPE.ALL_VIEW.name(),
				VIEW_TYPE.TIME_WINDOW_VIEW.name(),
				VIEW_TYPE.ADDR_WINDOW_VIEW.name()
				};
	}

	@Override
	public String[] getViewParams(String name) {
		switch (VIEW_TYPE.valueOf(name)) {
		case TIME_WINDOW_VIEW:
			return new String[] { VIEW_PARAM.TIME_START.name(), VIEW_PARAM.TIME_END.name() };
		case ALL_VIEW:
			return new String[] {  };
		case ADDR_WINDOW_VIEW:
			return new String[] { VIEW_PARAM.ADDR_START.name(), VIEW_PARAM.ADDR_END.name() };
		}
		return new String[] {};
	}

	@Override
	public String getViewTypeName() {
		return this.viewType.name();
	}

	@Override
	public Long getViewParam(String name) {
		if (this.viewParams.containsKey(name)) {
			return this.viewParams.get(name);
		}
		return null;
	}

	@Override
	public void setViewParam(String name, Long val) {
		this.viewParams.put(name, val);
	}

	@Override
	public View deepCopy() {
		ObjectManagerView copy = new ObjectManagerView();
		copy.viewType = this.viewType;
		copy.viewParams = new HashMap<String, Long>(this.viewParams);
		return copy;
	}

}
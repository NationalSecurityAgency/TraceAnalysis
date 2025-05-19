package tracemadness.memorylisting;

import java.util.HashMap;
import java.util.Map;

import tracemadness.View;

public class MemoryListingView implements View {

	public static enum VIEW_TYPE {
		ADDR_WINDOW_VIEW
	}

	public static enum VIEW_PARAM {
		ADDR_START, LEN, TICK
	}
	public Long lastAddress;
	
	public VIEW_TYPE viewType;

	public Map<String, Long> viewParams;

	public MemoryListingView() {
		this.viewType = VIEW_TYPE.ADDR_WINDOW_VIEW;
		this.viewParams = new HashMap<String, Long>();
		this.viewParams.put(VIEW_PARAM.ADDR_START.name(), 0L);
		this.viewParams.put(VIEW_PARAM.LEN.name(), 0x1000L);
		this.viewParams.put(VIEW_PARAM.TICK.name(), 1L);
	}

	public MemoryListingView(String ty, Map<String, Long> params) {
		this.viewType = VIEW_TYPE.valueOf(ty);
		this.viewParams = new HashMap<String, Long>(params);
	}

	public String toString() {
		switch (this.viewType) {
		case ADDR_WINDOW_VIEW:
			return String.format("Address in [0x%x, 0x%x] at time %d",
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()),
					this.viewParams.get(VIEW_PARAM.LEN.name()),
					this.viewParams.get(VIEW_PARAM.TICK.name()));
		}
		return "";
	}

	public String toAQLString() {
		return "";
	}

	public void setViewType(String ty) {
		this.viewType = VIEW_TYPE.valueOf(ty);
	}

	public String[] getViewTypes() {
		int l = VIEW_TYPE.values().length;
		String[] ans = new String[l];
		for (int i = 0; i < l; i++) {
			ans[i] = VIEW_TYPE.values()[i].name();
		}
		return ans;
	}

	public String[] getViewParams(String name) {
		switch (VIEW_TYPE.valueOf(name)) {
		case ADDR_WINDOW_VIEW:
			return new String[] { VIEW_PARAM.ADDR_START.name(), VIEW_PARAM.LEN.name(), VIEW_PARAM.TICK.name() };
		}
		return null;
	}

	public String getViewTypeName() {
		return this.viewType.name();
	}

	public Long getViewParam(String name) {
		if (this.viewParams.containsKey(name)) {
			return this.viewParams.get(name);
		}
		return null;

	}

	public void setViewParam(String name, Long val) {
		this.viewParams.put(name, val);
	}

	public MemoryListingView deepCopy() {
		MemoryListingView copy = new MemoryListingView();
		copy.viewType = this.viewType;
		copy.viewParams = new HashMap<String, Long>(this.viewParams);
		return copy;
	}

}
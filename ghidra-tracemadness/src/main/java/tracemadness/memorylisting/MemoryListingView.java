package tracemadness.memorylisting;

import java.util.HashMap;
import java.util.Map;

import tracemadness.View;

public class MemoryListingView implements View {

	public static enum VIEW_TYPE {
		ADDR_WINDOW_VIEW
	}

	public static enum VIEW_PARAM {
		ADDR_START, ADDR_END, TIME_START, TIME_END
	}
	public Long lastAddress;
	
	public VIEW_TYPE viewType;

	public Map<String, Long> viewParams;

	public MemoryListingView() {
		this.viewType = VIEW_TYPE.ADDR_WINDOW_VIEW;
		this.viewParams = new HashMap<String, Long>();
		this.viewParams.put(VIEW_PARAM.TIME_START.name(), 1L);
		this.viewParams.put(VIEW_PARAM.TIME_END.name(), 100L);
	}

	public MemoryListingView(String ty, Map<String, Long> params) {
		this.viewType = VIEW_TYPE.valueOf(ty);
		this.viewParams = new HashMap<String, Long>(params);
	}

	public String toString() {
		switch (this.viewType) {
		case ADDR_WINDOW_VIEW:
			return String.format("Address in [0x%x, 0x%x]",
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()));
		}
		return "";
	}

	public String toAQLString() {
		switch (this.viewType) {
		case ADDR_WINDOW_VIEW:
			return String.format("for n in range(%d, %d)\n"
					+ "  for op in operationruns filter op.addr == n or op.assocd_addr == n\n",
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()),
					this.viewParams.get(VIEW_PARAM.TIME_START.name()),
					this.viewParams.get(VIEW_PARAM.TIME_END.name()));
		}
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
			return new String[] { VIEW_PARAM.ADDR_START.name(), VIEW_PARAM.ADDR_END.name() };
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
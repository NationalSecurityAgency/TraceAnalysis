package tracemadness.witnessmanager;

import java.util.HashMap;
import java.util.Map;

import tracemadness.View;

public class WitnessManagerView implements View {

	public static enum VIEW_TYPE {
		ALL_VIEW
	}

	public static enum VIEW_PARAM {
		
	}

	public VIEW_TYPE viewType;
	public Map<String, Long> viewParams;

	public WitnessManagerView() {
		this.viewType = VIEW_TYPE.ALL_VIEW;
		this.viewParams = new HashMap<String, Long>();
	}

	public WitnessManagerView(String ty, Map<String, Long> params) {
		this.viewType = VIEW_TYPE.valueOf(ty);
		this.viewParams = new HashMap<String, Long>(params);
	}

	public String toString() {
		switch (this.viewType) {
		case ALL_VIEW:
			return String.format("All witnesses");
		}
		return "";
	}

	public String toAQLString() {
		switch (this.viewType) {
		case ALL_VIEW:
			return String.format("for w in witnesses \n");
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
				};
	}

	@Override
	public String[] getViewParams(String name) {
		switch (VIEW_TYPE.valueOf(name)) {
		case ALL_VIEW:
			return new String[] {  };
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
		WitnessManagerView copy = new WitnessManagerView();
		copy.viewType = this.viewType;
		copy.viewParams = new HashMap<String, Long>(this.viewParams);
		return copy;
	}

}
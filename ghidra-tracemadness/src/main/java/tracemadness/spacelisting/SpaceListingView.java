package tracemadness.spacelisting;

import java.util.HashMap;
import java.util.Map;

import tracemadness.View;

public class SpaceListingView implements View {

	public static enum VIEW_TYPE {
		ADDR_WINDOW_VIEW, TIME_WINDOW_VIEW, ADDR_TIME_WINDOW_VIEW, FUNCTION_RUN_VIEW, VALUE_VIEW
	}

	public static enum VIEW_PARAM {
		ADDR_START, ADDR_END, TIME_START, TIME_END, VALUE
	}
	public Long lastAddress;
	
	public VIEW_TYPE viewType;

	public Map<String, Long> viewParams;

	public SpaceListingView() {
		this.viewType = VIEW_TYPE.TIME_WINDOW_VIEW;
		this.viewParams = new HashMap<String, Long>();
		this.viewParams.put(VIEW_PARAM.TIME_START.name(), 1L);
		this.viewParams.put(VIEW_PARAM.TIME_END.name(), 100L);
	}

	public SpaceListingView(String ty, Map<String, Long> params) {
		this.viewType = VIEW_TYPE.valueOf(ty);
		this.viewParams = new HashMap<String, Long>(params);
	}

	public String toString() {
		switch (this.viewType) {
		case ADDR_WINDOW_VIEW:
			return String.format("Address in [0x%x, 0x%x]",
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()));
		case TIME_WINDOW_VIEW:
			return String.format("Tick in [%d, %d]",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()),
					this.viewParams.get(VIEW_PARAM.TIME_END.name()));
		case ADDR_TIME_WINDOW_VIEW:
			return String.format("Tick in [%d, %d], address in [%d, %d]",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()),
					this.viewParams.get(VIEW_PARAM.TIME_END.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()));
		case FUNCTION_RUN_VIEW:
			return String.format("During function run containing tick %d",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()));
		case VALUE_VIEW:
			return String.format("Value == %d",
					this.viewParams.get(VIEW_PARAM.VALUE.name()));
		}
		return "";
	}

	public String toAQLString() {
		switch (this.viewType) {
		case ADDR_WINDOW_VIEW:
			return String.format("for n in range(%d, %d)\n"
					+ "  for op in operationruns filter op.addr == n or op.assocd_addr == n\n",
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()));
		case TIME_WINDOW_VIEW:
			return String.format("for n in range(%d, %d)\n"
					+ "  for op in operationruns filter op.tick == n \n"
					+ "  filter (op.opcode == 2 or op.opcode == 3 or op.opcode == 74)\n",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()),
					this.viewParams.get(VIEW_PARAM.TIME_END.name()));
		case ADDR_TIME_WINDOW_VIEW:
			return String.format("let inittick=%d\n"
					+ "let finaltick=%d\n"
					+ "let initaddr=%d\n"
					+ "let finaladdr=%d\n"
					+ "\n"
					+ "  for op in operationruns filter op.tick >= inittick and op.tick <= finaltick \n"
					+ "  filter (op.opcode == 2 and op.assocd_addr >= initaddr and op.assocd_addr < finaladdr)\n"
					+ "  	or (op.bank == 1 and op.addr >= initaddr and op.addr < finaladdr)\n",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()),
					this.viewParams.get(VIEW_PARAM.TIME_END.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()));
		case FUNCTION_RUN_VIEW:
			return String.format("for ii in instructionruns filter ii.tick == %d\n"
					+ "for rr,rre in 1..1 outbound ii infunctionrun\n"
					+ "let endtick=first(for oo in operationruns filter oo.index == rr.endindex return oo.tick)\n"
					+ "for n in range(rr.starttick,endtick)\n"
					+ "  for op in operationruns filter op.tick == n \n"
					+ "  filter (op.opcode == 2 or op.opcode == 3 or op.opcode == 74)\n",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()));
		case VALUE_VIEW:
			return String.format("for op in operationruns filter op.val == %d \n"
					+ "  filter (op.opcode == 2 or op.opcode == 3 or op.opcode == 74)\n",
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
		case TIME_WINDOW_VIEW:
			return new String[] { VIEW_PARAM.TIME_START.name(), VIEW_PARAM.TIME_END.name() };
		case ADDR_TIME_WINDOW_VIEW:
			return new String[] { VIEW_PARAM.ADDR_START.name(), VIEW_PARAM.ADDR_END.name(), VIEW_PARAM.TIME_START.name(), VIEW_PARAM.TIME_END.name() };
		case FUNCTION_RUN_VIEW:
			return new String[] { VIEW_PARAM.TIME_START.name() };
		case VALUE_VIEW:
			return new String[] { VIEW_PARAM.VALUE.name() };
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

	public SpaceListingView deepCopy() {
		SpaceListingView copy = new SpaceListingView();
		copy.viewType = this.viewType;
		copy.viewParams = new HashMap<String, Long>(this.viewParams);
		return copy;
	}

}
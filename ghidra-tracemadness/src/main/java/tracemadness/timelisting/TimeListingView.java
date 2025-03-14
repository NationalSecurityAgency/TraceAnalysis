package tracemadness.timelisting;

import java.util.HashMap;
import java.util.Map;

import tracemadness.View;

public class TimeListingView implements View {

	public static enum VIEW_TYPE {
		ADDR_WINDOW_VIEW, TIME_WINDOW_VIEW, ADDR_TIME_WINDOW_VIEW, VALUE_VIEW, ACCESSOR_VIEW, OBJ_ACCESSOR_VIEW, BACKWARDSSLICE_VIEW,	FORWARDSSLICE_VIEW, CALLER_VIEW, CALLEE_VIEW, OTHER_VIEW
	}

	public static enum VIEW_PARAM {
		ADDR_START, ADDR_END, TIME_START, TIME_END, INDEX, DEPTH, VALUE
	}
	public Long lastTick;
	
	public VIEW_TYPE viewType;

	public Map<String, Long> viewParams;
	public String viewQuery;
	public String viewDescription;

	public TimeListingView() {
		this.viewType = VIEW_TYPE.TIME_WINDOW_VIEW;
		this.viewParams = new HashMap<String, Long>();
		this.viewParams.put(VIEW_PARAM.TIME_START.name(), 1L);
		this.viewParams.put(VIEW_PARAM.TIME_END.name(), 100L);
	}

	public TimeListingView(String ty, Map<String, Long> params) {
		this.viewType = VIEW_TYPE.valueOf(ty);
		this.viewParams = new HashMap<String, Long>(params);
	}
	
	public TimeListingView(String query, String desc) {
		this.viewType = VIEW_TYPE.OTHER_VIEW;
		this.viewQuery = query;
		this.viewDescription = desc;
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
			return String.format("Tick in [%d, %d] and access in [0x%x, 0x%x]",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()),
					this.viewParams.get(VIEW_PARAM.TIME_END.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()));
		case VALUE_VIEW:
			return String.format("Value == %d",
					this.viewParams.get(VIEW_PARAM.VALUE.name()));
		case ACCESSOR_VIEW:
			return String.format("Accessors of addresses in [0x%x, 0x%x]", 
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()), 
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()));
		case OBJ_ACCESSOR_VIEW:
			return String.format("Accessors of addresses in [0x%x, 0x%x] in time [0x%d, 0x%d]", 
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()), 
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()), 
					this.viewParams.get(VIEW_PARAM.TIME_START.name()), 
					this.viewParams.get(VIEW_PARAM.TIME_END.name()));
		case BACKWARDSSLICE_VIEW:
			return String.format("Backwards slice from index %d to depth %d",
					this.viewParams.get(VIEW_PARAM.INDEX.name()), this.viewParams.get(VIEW_PARAM.DEPTH.name()));
		case FORWARDSSLICE_VIEW:
			return String.format("Forwards slice from index %d to depth %d",
					this.viewParams.get(VIEW_PARAM.INDEX.name()), this.viewParams.get(VIEW_PARAM.DEPTH.name()));
		case CALLER_VIEW:
			return String.format("Callers of function running at tick %d to depth %d",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()), this.viewParams.get(VIEW_PARAM.DEPTH.name()));
		case CALLEE_VIEW:
			return String.format("Callees of function running at tick %d to depth %d",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()), this.viewParams.get(VIEW_PARAM.DEPTH.name()));
		case OTHER_VIEW:
			return this.viewDescription;
		}
		return "";
	}

	public String toAQLString() {
		switch (this.viewType) {
		case ADDR_WINDOW_VIEW:
			return String.format("let instructions=(for ins in instructionruns\n"
					+ "filter ins.pc >= %d and ins.pc <= %d\n"
					+ "return ins)"
					+ "let relevant_indices = {empty:true}\n",
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()));
		case TIME_WINDOW_VIEW:
			return String.format("let relevant_indices = {empty:true}\n"
					+ "let instructions = (\n"
					+ "    for ttt in range(%d, %d)\n"
					+ "    for iii in instructionruns filter iii.tick == ttt\n"
					+ "    sort iii.tick\n"
					+ "    return iii\n" + ")\n",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()),
					this.viewParams.get(VIEW_PARAM.TIME_END.name()));
		case ADDR_TIME_WINDOW_VIEW:
			return String.format("let relevant_indices = {empty:true}\n"
					+ "let startaddr = %d\n"
					+ "let endaddr = %d\n"
					+ "let begintick = %d\n"
					+ "let endingtick = %d\n"
					+ "let instructions = (\n"
					+ "    for ooo in operationruns filter ooo.tick >= begintick and ooo.tick <= endingtick\n"
					+ "    filter (ooo.opcode == 2 and ooo.assocd_addr >= startaddr and ooo.assocd_addr <= endaddr)\n"
					+ "       or (ooo.bank == 1 and ooo.addr >= startaddr and ooo.addr <= endaddr)\n"
					+ "    for iii in instructionruns filter iii.tick == ooo.tick\n"
					+ "    sort iii.tick\n"
					+ "    return distinct iii\n" + ")\n",
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()),
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()),
					this.viewParams.get(VIEW_PARAM.TIME_START.name()),
					this.viewParams.get(VIEW_PARAM.TIME_END.name()));
		case VALUE_VIEW:
			return String.format(
					  "let sliceops=(\n"
					+ "for ooo in operationruns filter ooo.val == %d\n" 
					+ "for a,ae in 0..1 outbound ooo addrdep\n"
					+ "  return a)\n"
					+ "let relevant_indices=merge(for op in sliceops return {[op.index]:true})\n" + "\n"
					+ "let instructions = (\n"
					+ "	for op in sliceops\n"
					+ "	for ins in instructionruns filter op.tick == ins.tick\n"
					+ "	return distinct ins\n"
					+ ")\n",
					this.viewParams.get(VIEW_PARAM.VALUE.name()));
		case ACCESSOR_VIEW:
			return String.format("for access_addr in range(%d, %d)\n"
					+ "let sliceops=(\n"
					+ "for ooo in operationruns filter (ooo.bank == 1 and ooo.addr == access_addr) or (ooo.assocd_bank == 1 and ooo.assocd_addr == access_addr)\n" 
					+ "for a,ae in 0..1 outbound ooo addrdep\n"
					+ "  return a)\n" + "\n"
					+ "let relevant_indices=merge(for op in sliceops return {[op.index]:true})\n"
					+ "\n"
					+ "let instructions = (\n"
					+ "	for op in sliceops\n"
					+ "	for ins in instructionruns filter op.tick == ins.tick\n"
					+ "	return distinct ins\n"
					+ ")\n"
					+ "\n",
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()), this.viewParams.get(VIEW_PARAM.ADDR_END.name()));
		case OBJ_ACCESSOR_VIEW:
			return String.format("for access_addr in range(%d, %d)\n"
					+ "let thestarttick=%d\n"
					+ "let theendtick=%d\n"
					+ "let sliceops=(\n"
					+ "for ooo in operationruns filter (ooo.bank == 1 and ooo.addr == access_addr) or (ooo.assocd_bank == 1 and ooo.assocd_addr == access_addr)\n"
					+ "filter ooo.tick >= thestarttick and ooo.tick <= theendtick\n" 
					+ "for a,ae in 0..1 outbound ooo addrdep\n"
					+ "  return a)\n" + "\n"
					+ "let relevant_indices=merge(for op in sliceops return {[op.index]:true})\n"
					+ "\n"
					+ "let instructions = (\n"
					+ "	for op in sliceops\n"
					+ "	for ins in instructionruns filter op.tick == ins.tick\n"
					+ "	return distinct ins\n"
					+ ")\n"
					+ "\n",
					this.viewParams.get(VIEW_PARAM.ADDR_START.name()), 
					this.viewParams.get(VIEW_PARAM.ADDR_END.name()),
					this.viewParams.get(VIEW_PARAM.TIME_START.name()), 
					this.viewParams.get(VIEW_PARAM.TIME_END.name()));
		case BACKWARDSSLICE_VIEW:
			return String.format(
					"let backward_on_index = %d\n"
							+ "let depth = %d\n"
							+ "\n"
							+ "let calcdeps=(\n"
							+ "	for op in operationruns filter op.index == backward_on_index\n"
							+ "	for v,e in 0..depth outbound op inputdep\n"
							+ "	return v)\n" + "\n"
							+ "let addrdeps=(for x in calcdeps for a,ae in 1..1 outbound x addrdep return a)\n" + "\n"
							+ "let sliceops = append(calcdeps, addrdeps)\n" + "\n"
							+ "let relevant_indices=merge(for op in sliceops return {[op.index]:true})\n" + "\n"
							+ "let instructions = (\n"
							+ "	for op in sliceops\n"
							+ "	for ins in instructionruns filter op.tick == ins.tick\n"
							+ "	return distinct ins\n"
							+ ")\n",
					this.viewParams.get(VIEW_PARAM.INDEX.name()), this.viewParams.get(VIEW_PARAM.DEPTH.name()));
		case FORWARDSSLICE_VIEW:
			return String.format(
					"let forward_on_index = %d\n"
							+ "let depth = 50\n" + "\n"
							+ "let calcdeps=(\n"
							+ "	for op in operationruns filter op.index == forward_on_index\n"
							+ "	for v,e in 0..depth inbound op inputdep\n"
							+ "	return v)\n" + "\n"
							+ "let addrdeps=(for x in calcdeps for a,ae in 1..1 inbound x addrdep return a)\n" + "\n"
							+ "let sliceops = append(calcdeps, addrdeps)\n" + "\n"
							+ "let relevant_indices=merge(for op in sliceops return {[op.index]:true})\n" + "\n"
							+ "let instructions = (\n"
							+ "	for op in sliceops\n"
							+ "	for ins in instructionruns filter op.tick == ins.tick\n"
							+ "	return distinct ins\n"
							+ ")\n",
					this.viewParams.get(VIEW_PARAM.INDEX.name()), this.viewParams.get(VIEW_PARAM.DEPTH.name()));
		case CALLER_VIEW:
			return String.format(
					  "let instructions=(for ins in instructionruns filter ins.tick == %d \n"
					+ "for r,re in 1..1 outbound ins infunctionrun\n"
					+ "for c,ce in 0..%d inbound r calls\n"
					+ "let callins=first(for n in range(0,10) for ins2 in instructionruns filter ins2.tick == c.starttick-n and ins2.pc == c.callsite limit 1 return ins2)\n"
					+ "sort callins.tick \n"
					+ "return distinct callins)\n"
					+ "let relevant_indices = {empty:true}\n",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()), this.viewParams.get(VIEW_PARAM.DEPTH.name()));
		case CALLEE_VIEW:
			return String.format(
					  "let instructions=(for ins in instructionruns filter ins.tick == %d \n"
					+ "for r,re in 1..1 outbound ins infunctionrun\n"
					+ "for c,ce in 0..%d outbound r calls\n"
					+ "let callins=first(for n in range(0,10) for ins2 in instructionruns filter ins2.tick == c.starttick-n and ins2.pc == c.callsite limit 1 return ins2)\n"
					+ "sort callins.tick \n"
					+ "return distinct callins)\n"
					+ "let relevant_indices = {empty:true}\n",
					this.viewParams.get(VIEW_PARAM.TIME_START.name()), this.viewParams.get(VIEW_PARAM.DEPTH.name()));
		case OTHER_VIEW:
			return this.viewQuery;
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
		case VALUE_VIEW:
			return new String[] { VIEW_PARAM.VALUE.name() };
		case ACCESSOR_VIEW:
			return new String[] { VIEW_PARAM.ADDR_START.name(), VIEW_PARAM.ADDR_END.name() };
		case OBJ_ACCESSOR_VIEW:
			return new String[] { VIEW_PARAM.ADDR_START.name(), VIEW_PARAM.ADDR_END.name(), VIEW_PARAM.TIME_START.name(), VIEW_PARAM.TIME_END.name() };
		case BACKWARDSSLICE_VIEW:
			return new String[] { VIEW_PARAM.INDEX.name(), VIEW_PARAM.DEPTH.name() };
		case FORWARDSSLICE_VIEW:
			return new String[] { VIEW_PARAM.INDEX.name(), VIEW_PARAM.DEPTH.name() };
		case CALLER_VIEW:
			return new String[] { VIEW_PARAM.TIME_START.name(), VIEW_PARAM.DEPTH.name() };
		case CALLEE_VIEW:
			return new String[] { VIEW_PARAM.TIME_START.name(), VIEW_PARAM.DEPTH.name() };
		case OTHER_VIEW:
			return new String[] {  };
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

	public TimeListingView deepCopy() {
		TimeListingView copy = new TimeListingView();
		copy.viewType = this.viewType;
		copy.viewParams = new HashMap<String, Long>(this.viewParams);
		return copy;
	}

}
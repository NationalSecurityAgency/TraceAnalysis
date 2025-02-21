package tracemadness.objectdata;

import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.data.DataType;

public class ObjectInfo {

	private String key;
	private String name;
	private Long birth;
	private Long death;
	private Long base;
	private Long size;
	private TreeMap<Long, ObjectPhase> timeline;

	public ObjectInfo(String key, String name, Long size, Long base, Long birth, Long death, ObjectPhase[] tl) {
		this.key = key;
		this.name = name;
		this.size = size;
		this.birth = birth;
		this.death = death;
		this.base = base;
		this.timeline = new TreeMap<>();
		for(int i = 0; i < tl.length; i++) {
			this.timeline.put(tl[i].getStart(), tl[i]);
		}
	}
	
	public String getKey() {
		return this.key;
	}

	public String getName() {
		return this.name;
	}

	public Long getBase() {
		return this.base;
	}

	public Long getSize() {
		return this.size;
	}
	
	public Long getBirth() {
		return this.birth;
	}

	public Long getDeath() {
		return this.death;
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public void setBirth(Long birth) {
		this.birth = birth;
		Map.Entry<Long, ObjectPhase> firstEntry = this.timeline.floorEntry(birth);
		if(firstEntry == null) {
			// we are adjusting the birth to be earlier than the current first phase
			firstEntry = this.timeline.ceilingEntry(birth);
			if(firstEntry == null) {
				// should never happen
				return;
			}
			ObjectPhase firstPhase = firstEntry.getValue();
			this.timeline.remove(firstPhase.getStart());
			firstPhase.setStart(birth);
			this.timeline.put(this.birth, firstPhase);
		} else {
			// we are adjusting the birth to be later than it was previously, so delete any stale phases now prior to the new birth time
			ObjectPhase firstPhase = firstEntry.getValue();
			ArrayList<Long> stale = new ArrayList<>();
			for(Long k : this.timeline.navigableKeySet()) {
				// make sure to also remove the first phase since its start may change
				if(k <= firstPhase.getStart()) {
					stale.add(k);
				}
			}
			for(Long k : stale) {
				this.timeline.remove(k);
			}
			// Because we have remove the first phase (since its start needs to change) we re-add it with its new correct start tick
			this.timeline.put(this.birth, firstPhase);
		}
	}
	
	public void setDeath(Long death){
		this.death = death;
		Map.Entry<Long, ObjectPhase> lastEntry = this.timeline.floorEntry(this.death);
		ObjectPhase lastPhase = lastEntry.getValue();
		ArrayList<Long> stale = new ArrayList<>();
		for(Long k : this.timeline.navigableKeySet()) {
			// don't worry about removing the final phase since its start will not change
			if(k > lastPhase.getStart()) {
				stale.add(k);
			}
		}
		for(Long k : stale) {
			this.timeline.remove(k);
		}
		// because we did not remove the last phase (since its start did not need to change), we are now done
	}
	
	public ObjectPhase[] getTimeline() {
		ObjectPhase[] ans = new ObjectPhase[this.timeline.size()];
		int i = 0;
		for(Long tick : this.timeline.navigableKeySet()) {
			ans[i++] = this.timeline.get(tick);
		}
		return ans;
	}
	public void setPhaseType(Long start, DataType ty) {
		ObjectPhase phase = this.timeline.get(start);
		if(phase != null) {
			phase.setType(ty);
		}
	}
	public Long getPhaseEnd(ObjectPhase phase) {
		long start = phase.getStart();
		Map.Entry<Long, ObjectPhase> next = this.timeline.ceilingEntry(start+1);
		if(next == null) {
			return this.death;
		}
		return next.getKey()-1;
	}
	
	public String getTypeDescription() {
		if(this.timeline.size() == 0) {
			return String.format("unknown%d", this.size);
		}
		if(this.timeline.size() == 1) {
			return this.timeline.firstEntry().getValue().getType().getName();
		}
		return "multiple types...";
	}
	
	public void addPhase(ObjectPhase phase) {
		this.timeline.put(phase.getStart(), phase);
	}

	public void removePhase(ObjectPhase phase) {
		this.timeline.remove(phase.getStart());
	}
	
	public void setPhaseStart(ObjectPhase phase, Long start) {
		this.timeline.remove(phase.getStart());
		phase.setStart(start);
		this.timeline.put(phase.getStart(), phase);
	}
	
	public DataType getType(Long tick) {
		Long start = this.timeline.floorKey(tick);
		if(start == null) return null;
		ObjectPhase info = this.timeline.get(start);
		Long end = this.getPhaseEnd(info);
		if(end < tick) return null;
		return info.getType();
	}
}

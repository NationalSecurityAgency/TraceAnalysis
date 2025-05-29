package tracemadness.objectdata;

public class WitnessEvent implements Comparable<WitnessEvent> {
	public ObjectWitness witness;
	public Long tick;
	private Long addr;
	public WitnessEvent(ObjectWitness w, Long tick, Long addr) {
		this.witness = w;
		this.tick = tick;
		this.addr = addr;
	}
	public Long getAddr() {
		return this.addr - witness.objOffset;
	}
	public int compareTo(WitnessEvent w) {
		if(!this.witness.type.equals(w.witness.type)) {
			if(this.witness.type == ObjectWitness.eventType.BIRTH && w.witness.type != ObjectWitness.eventType.BIRTH) return -1;
			if(this.witness.type == ObjectWitness.eventType.CHANGE && w.witness.type == ObjectWitness.eventType.DEATH) return -1;
			return 1;
		}
		if(this.tick != w.tick) {
			return this.tick < w.tick ? -1 : 1;
		}
		if(this.addr != w.addr) {
			return this.addr < w.addr ? -1 : 1;
		}
		return 0;
	}
	public String toString() {
		return String.format("Tick:%d, Addr:0x%x, %s", this.tick, this.addr, this.witness.toString());
	}
}
package tracemadness.objectdata;

public class WitnessEvent {
	public ObjectWitness witness;
	public Long tick;
	public Long addr;
	public WitnessEvent(ObjectWitness w, Long tick, Long addr) {
		this.witness = w;
		this.tick = tick;
		this.addr = addr;
	}
}
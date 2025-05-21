package tracemadness.objectdata;

public class WitnessedObject {
	public ObjectWitness birthWitness;
	public ObjectWitness deathWitness;
	public ObjectInfo obj;
	public WitnessedObject(ObjectWitness birthWitness, ObjectWitness deathWitness, ObjectInfo obj) {
		this.birthWitness = birthWitness;
		this.deathWitness = deathWitness;
		this.obj = obj;
	}
	public String toString() {
		return String.format("%s (birth witness %s; death witness %s)", obj.toString(), birthWitness.toString(), deathWitness.toString());
	}
}
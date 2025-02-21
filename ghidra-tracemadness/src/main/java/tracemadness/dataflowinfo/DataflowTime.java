package tracemadness.dataflowinfo;

/**
 * This class should be extended by classes that model data that can be rendered in the time listing 
 */
public abstract class DataflowTime implements Comparable<DataflowTime> {
	public static final int FUNCTIONRUN = 0;
	public static final int INSTRUCTIONRUN = 1;
	public static final int SYSCALLRUN = 2;
	public long type;
	public long tick;
	public int compareTo(DataflowTime t2) {
		if(this.tick < t2.tick) return -1;
		if(this.tick > t2.tick) return 1;
		if(this.type < t2.type) return -1;
		if(this.type > t2.type) return 1;
		return 0;
	}
}

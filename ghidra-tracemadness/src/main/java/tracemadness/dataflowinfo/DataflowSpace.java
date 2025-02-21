package tracemadness.dataflowinfo;

/**
 * This class should be extended by classes that model data that can be rendered in the time listing 
 */
public abstract class DataflowSpace implements Comparable<DataflowSpace> {
	public long addr;
	public int compareTo(DataflowSpace t2) {
		if(this.addr < t2.addr) return -1;
		if(this.addr > t2.addr) return 1;
		return 0;
	}

}

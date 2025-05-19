package tracemadness.memsearchlisting;

public class MemSearchItem {

	public Long address;
	public Long create_tick;
	public Long destroy_tick;

	public MemSearchItem(long addr, long start, long end) {
		this.address = addr;
		this.create_tick = start;
		this.destroy_tick = end;
	}
}

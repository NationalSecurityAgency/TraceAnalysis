package tracemadness.modulemap;

public class ModuleInfo {

	private String name;
	private String path;
	private Long start;
	private Long size;

	public ModuleInfo(String name, String path, Long start, Long size) {
		this.name = name;
		this.path = path;
		this.start = start;
		this.size = size;
	}

	public String getName() {
		return this.name;
	}

	public String getPath() {
		return this.path;
	}

	public Long getBase() {
		return this.start;
	}

	public Long getSize() {
		return this.size;
	}
}

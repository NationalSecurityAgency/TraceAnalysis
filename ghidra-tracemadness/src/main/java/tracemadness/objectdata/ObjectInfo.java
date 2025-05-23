package tracemadness.objectdata;

import ghidra.program.model.data.DataType;

public class ObjectInfo {

	private String key;
	private String name;
	private Long birth;
	private Long death;
	private Long base;
	private Long size;
	private DataType ty;

	public ObjectInfo(String key, String name, Long size, Long base, Long birth, Long death, DataType ty) {
		this.key = key;
		this.name = name;
		this.size = size;
		this.birth = birth;
		this.death = death;
		this.base = base;
		this.ty = ty;
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
	}
	
	public void setDeath(Long death){
		this.death = death;
	}
	
	
	public String getTypeDescription() {
		return ty.getName();
	}
	
	public DataType getType() {
		return ty;
	}
	
	public void setType(DataType ty) {
		this.ty = ty;
	}
	public String toString() {
		return String.format("%s %s @ 0x%x (%s-%s)", ty.getName(), name, base, birth == null ? "?" : birth.toString(), death == null ? "?" : death.toString());
	}
}

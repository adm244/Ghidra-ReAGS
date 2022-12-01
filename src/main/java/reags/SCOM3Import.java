package reags;

public class SCOM3Import {

	private String name;
	private long offset;
	
	public SCOM3Import(String name, long offset) {
		this.name = name;
		this.offset = offset;
	}
	
	public String getName() {
		return name;
	}
	
	public long getOffset() {
		return offset;
	}
	
}

package reags.scom3;

public class ScriptImport {

	private String name;
	private long offset;
	
	public ScriptImport(String name, long offset) {
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

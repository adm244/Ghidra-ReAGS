package reags.scom3;

public class ScriptExport {

	public static final byte FUNCTION = 1;
	public static final byte DATA = 2;
	
	private String name;
	private byte type;
	private int offset;
	
	public ScriptExport(String name, byte type, int offset) {
		this.name = name;
		this.type = type;
		this.offset = offset;
	}
	
	public String getName() {
		return name;
	}
	
	public byte getType() {
		return type;
	}
	
	public int getOffset() {
		return offset;
	}
	
}

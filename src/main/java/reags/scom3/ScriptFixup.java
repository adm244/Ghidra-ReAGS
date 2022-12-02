package reags.scom3;

public class ScriptFixup {

	/**
	 * Immediate value
	 */
	public static final int LITERAL = 0;

	/**
	 * Offset into .data memory block pointing to data
	 */
	public static final int DATA = 1;

	/**
	 * Index into .code memory block as integers array
	 */
	public static final int FUNCTION = 2;

	/**
	 * Offset into .strings memory block pointing a to null-terminated string
	 */
	public static final int STRING = 3;

	/**
	 * Index into .imports memory block as strings array
	 */
	public static final int IMPORT = 4;

	/**
	 * Offset into .data memory block pointing to a pointer to data
	 */
	public static final int DATAPOINTER = 5;

	/**
	 * TODO: figure out what this value is actually about
	 */
	public static final int STACK = 6;

	private byte type;
	private int offset;

	public ScriptFixup() {
		// TODO Auto-generated constructor stub
	}

	public byte getType() {
		return type;
	}

	public void setType(byte type) {
		this.type = type;
	}

	public int getOffset() {
		return offset;
	}

	public void setOffset(int offset) {
		this.offset = offset;
	}

}

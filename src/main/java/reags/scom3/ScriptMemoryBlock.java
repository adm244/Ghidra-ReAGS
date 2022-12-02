package reags.scom3;

public class ScriptMemoryBlock {

	private String name;
	private byte[] data;

	private boolean canRead;
	private boolean canWrite;
	private boolean canExecute;

	public ScriptMemoryBlock(String name, byte[] data, boolean canRead, boolean canWrite, boolean canExecute) {
		this.name = name;
		this.data = data;
		this.canRead = canRead;
		this.canWrite = canWrite;
		this.canExecute = canExecute;
	}

	public String getName() {
		return name;
	}

	public byte[] getData() {
		return data;
	}

	public boolean getCanRead() {
		return canRead;
	}

	public boolean getCanWrite() {
		return canWrite;
	}

	public boolean getCanExecute() {
		return canExecute;
	}

}

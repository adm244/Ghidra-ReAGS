package reags.properties;

import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

public class ImportProperty implements Saveable {

	public static final int DEFAULT_SIZE = 4;

	private long baseOffset;
	private String name;
	private ImportType type;
	private int size;

	public ImportProperty() {
		this.baseOffset = 0;
		this.name = "";
		this.type = ImportType.UNKNOWN;
		this.size = DEFAULT_SIZE;
	}

	public ImportProperty(long baseOffset, String name) {
		this.baseOffset = baseOffset;
		this.name = name;
		this.type = ImportType.UNKNOWN;
		this.size = DEFAULT_SIZE;
	}

	@Override
	public Class<?>[] getObjectStorageFields() {
		return new Class<?>[] { String.class, Integer.class };
	}

	@Override
	public void save(ObjectStorage objStorage) {
		objStorage.putLong(baseOffset);
		objStorage.putString(name);
		objStorage.putInt(type.ordinal());
		objStorage.putInt(size);
	}

	@Override
	public void restore(ObjectStorage objStorage) {
		this.baseOffset = objStorage.getLong();
		this.name = objStorage.getString();

		int ordinal = objStorage.getInt();
		this.type = ImportType.values()[ordinal];

		this.size = objStorage.getInt();
	}

	@Override
	public int getSchemaVersion() {
		return 1;
	}

	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {
		return false;
	}

	@Override
	public boolean isPrivate() {
		return true;
	}

	public String getName() {
		return name;
	}

	public ImportType getType() {
		return type;
	}

	public void setType(ImportType type) {
		this.type = type;
	}

	public int getSize() {
		return size;
	}

	public void setSize(int size) {
		this.size = size;
	}

	public long getBaseOffset() {
		return baseOffset;
	}

}

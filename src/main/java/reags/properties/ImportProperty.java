package reags.properties;

import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

public class ImportProperty implements Saveable {

	private String name;
	private ImportType type;

	public ImportProperty() {
		this.name = "";
		this.type = ImportType.UNKNOWN;
	}

	public ImportProperty(String name) {
		this.name = name;
		this.type = ImportType.UNKNOWN;
	}

	@Override
	public Class<?>[] getObjectStorageFields() {
		return new Class<?>[] { String.class, Integer.class };
	}

	@Override
	public void save(ObjectStorage objStorage) {
		objStorage.putString(name);
		objStorage.putInt(type.ordinal());
	}

	@Override
	public void restore(ObjectStorage objStorage) {
		this.name = objStorage.getString();

		int ordinal = objStorage.getInt();
		this.type = ImportType.values()[ordinal];
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

}

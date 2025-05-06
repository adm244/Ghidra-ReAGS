/*
 * This is free and unencumbered software released into the public domain.
 * 
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 * 
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
*/

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

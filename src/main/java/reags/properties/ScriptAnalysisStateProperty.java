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

import java.util.HashMap;
import java.util.Map.Entry;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;
import reags.analyzers.FixupType;
import reags.state.ExternalFunction;

public class ScriptAnalysisStateProperty implements Saveable {

	public HashMap<Address, FixupType> fixups;
	public HashMap<Long, String> strings;
	public HashMap<Long, String> imports;
	public HashMap<Long, ExternalFunction> functions;
	public HashMap<Long, String> data;

	public ScriptAnalysisStateProperty() {
		fixups = new HashMap<Address, FixupType>();
	}

	@Override
	public Class<?>[] getObjectStorageFields() {
		// TODO Auto-generated method stub
		return null;
	}

	private void saveAddress(ObjectStorage objStorage, Address address) {
		AddressSpace addressSpace = address.getAddressSpace();
		objStorage.putInt(addressSpace.getSpaceID());
		objStorage.putLong(address.getOffset());
	}

	private void saveFixups(ObjectStorage objStorage) {
		objStorage.putInt(fixups.size());
		for (Entry<Address, FixupType> entry : fixups.entrySet()) {
			saveAddress(objStorage, entry.getKey());
			objStorage.putInt(entry.getValue().ordinal());
		}
	}

	private void saveStrings(ObjectStorage objStorage) {
		
	}

	@Override
	public void save(ObjectStorage objStorage) {
		saveFixups(objStorage);
		saveStrings(objStorage);
	}

	@Override
	public void restore(ObjectStorage objStorage) {
		// TODO Auto-generated method stub

	}

	@Override
	public int getSchemaVersion() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isPrivate() {
		// TODO Auto-generated method stub
		return false;
	}

}

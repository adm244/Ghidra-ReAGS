package reags;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class SCOM3Script {

	public static final String SCOM3_SIGNATURE = "SCOM";
	public static final int SCOM3_FOOTER = 0xBEEFCAFE;
	public static final int SCOM3_FOOTER_OFFSET = 4;

	private int version;

	private byte[] data;
	private byte[] code;
	private byte[] strings;
	private byte[] fixups;
	private byte[] imports;
	private byte[] exports;
	private byte[] sections;
	
	private int fixupsCount;
	private int importsCount;
	private int exportsCount;
	private int sectionsCount;

	public SCOM3Script(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);

		String signature = reader.readNextAsciiString(SCOM3_SIGNATURE.length());
		if (signature.equals(SCOM3_SIGNATURE)) {
			version = reader.readNextInt();

			int dataSize = reader.readNextInt();
			// NOTE(adm244): code size stored as int32 array size
			int codeSize = reader.readNextInt() * 4;
			int stringsSize = reader.readNextInt();

			data = reader.readNextByteArray(dataSize);
			code = reader.readNextByteArray(codeSize);
			strings = reader.readNextByteArray(stringsSize);

			fixupsCount = reader.readNextInt();
			int fixupsSize = fixupsCount + fixupsCount * 4;

			fixups = reader.readNextByteArray(fixupsSize);

			imports = readImports(reader);
			exports = readExports(reader);
			sections = readSections(reader);

			int footer = reader.readNextInt();
			if (footer != SCOM3_FOOTER) {
				throw new IOException();
			}
		}
	}

	private byte[] readImports(BinaryReader reader) throws IOException {
		importsCount = reader.readNextInt();
		long importsStart = reader.getPointerIndex();
		
		for (int i = 0; i < importsCount; ++i) {
			reader.readNextAsciiString();
		}

		long importsEnd = reader.getPointerIndex();
		int importsSize = (int) (importsEnd - importsStart);

		return reader.readByteArray(importsStart, importsSize);
	}

	private byte[] readExports(BinaryReader reader) throws IOException {
		exportsCount = reader.readNextInt();
		long exportsStart = reader.getPointerIndex();

		for (int i = 0; i < exportsCount; ++i) {
			reader.readNextAsciiString();
			reader.readNextUnsignedInt();
		}

		long exportsEnd = reader.getPointerIndex();
		int exportsSize = (int) (exportsEnd - exportsStart);

		return reader.readByteArray(exportsStart, exportsSize);
	}
	
	private byte[] readSections(BinaryReader reader) throws IOException {
		sectionsCount = reader.readNextInt();
		long sectionsStart = reader.getPointerIndex();

		for (int i = 0; i < sectionsCount; ++i) {
			reader.readNextAsciiString();
			reader.readNextUnsignedInt();
		}

		long sectionsEnd = reader.getPointerIndex();
		int sectionsSize = (int) (sectionsEnd - sectionsStart);

		return reader.readByteArray(sectionsStart, sectionsSize);
	}
	
	public int getVersion() {
		return version;
	}

	public byte[] getData() {
		return data;
	}

	public byte[] getCode() {
		return code;
	}

	public byte[] getStrings() {
		return strings;
	}

	public byte[] getFixups() {
		return fixups;
	}

	public byte[] getImports() {
		return imports;
	}

	public byte[] getExports() {
		return exports;
	}

	public byte[] getSections() {
		return sections;
	}
	
	public int getFixupsCount() {
		return fixupsCount;
	}
	
	public int getImportsCount() {
		return importsCount;
	}
	
	public int getExportsCount() {
		return exportsCount;
	}
	
	public int getSectionsCount() {
		return sectionsCount;
	}

}

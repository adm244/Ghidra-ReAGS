package reags.scom3;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class Script {

	private static final String SCOM3_SIGNATURE = "SCOM";
	private static final int SCOM3_FOOTER = 0xBEEFCAFE;
	private static final int SCOM3_FOOTER_OFFSET = 4;

	private int version;

	private byte[] data;
	private byte[] code;
	private byte[] strings;
	private byte[] fixups;
	private byte[] imports;
	private byte[] exports;
	private byte[] sections;

	public Script(ByteProvider provider) throws IOException {
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

			fixups = readFixups(reader);
			imports = readImports(reader);
			exports = readExports(reader);
			sections = readSections(reader);

			int footer = reader.readNextInt();
			if (footer != SCOM3_FOOTER) {
				throw new IOException();
			}
		}
	}

	public static boolean isValid(ByteProvider provider) {
		boolean result = false;

		try {
			BinaryReader reader = new BinaryReader(provider, true);
			String signature = reader.readAsciiString(0, Script.SCOM3_SIGNATURE.length());

			// TODO(adm244): maybe check file version?

			if (signature.equals(Script.SCOM3_SIGNATURE)) {
				long footerPosition = reader.length() - Script.SCOM3_FOOTER_OFFSET;

				if (reader.isValidIndex(footerPosition)) {
					int footer = reader.readInt(footerPosition);

					if (footer == Script.SCOM3_FOOTER) {
						result = true;
					}
				}
			}
		} catch (IOException e) {
			// if file can't be read then it's invalid
		}

		return result;
	}

	private byte[] readFixups(BinaryReader reader) throws IOException {
		int fixupsCount = reader.peekNextInt();
		int fixupsSize = fixupsCount + fixupsCount * 4;

		return reader.readNextByteArray(fixupsSize + 4);
	}

	private byte[] readImports(BinaryReader reader) throws IOException {
		long importsStart = reader.getPointerIndex();
		int importsCount = reader.readNextInt();

		for (int i = 0; i < importsCount; ++i) {
			reader.readNextAsciiString();
		}

		long importsEnd = reader.getPointerIndex();
		int importsSize = (int) (importsEnd - importsStart);

		return reader.readByteArray(importsStart, importsSize);
	}

	private byte[] readExports(BinaryReader reader) throws IOException {
		long exportsStart = reader.getPointerIndex();
		int exportsCount = reader.readNextInt();

		for (int i = 0; i < exportsCount; ++i) {
			reader.readNextAsciiString();
			reader.readNextUnsignedInt();
		}

		long exportsEnd = reader.getPointerIndex();
		int exportsSize = (int) (exportsEnd - exportsStart);

		return reader.readByteArray(exportsStart, exportsSize);
	}

	private byte[] readSections(BinaryReader reader) throws IOException {
		long sectionsStart = reader.getPointerIndex();
		int sectionsCount = reader.readNextInt();

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

}

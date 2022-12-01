/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reags;

import java.awt.Color;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.InputStreamByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.viewer.listingpanel.PropertyBasedBackgroundColorModel;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.IntRangeMap;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class ReAGSLoader extends AbstractProgramWrapperLoader {

	private final String LOADER_NAME = "Adventure Game Studio compiled script (scom3)";
	private final long IMAGE_BASE = 0x100000;

	private final String SCOM3_LANGUAGE_ID = "AGSVM:LE:32:default";
	private final String SCOM3_COMPILER_ID = "default";

	private FlatProgramAPI api;
	private Memory memory;

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);

		String signature = reader.readAsciiString(0, SCOM3Script.SCOM3_SIGNATURE.length());

		// TODO(adm244): maybe check file version?

		if (signature.equals(SCOM3Script.SCOM3_SIGNATURE)) {
			long footerPosition = reader.length() - SCOM3Script.SCOM3_FOOTER_OFFSET;

			if (reader.isValidIndex(footerPosition)) {
				int footer = reader.readInt(footerPosition);

				if (footer == SCOM3Script.SCOM3_FOOTER) {
					loadSpecs.add(new LoadSpec(this, IMAGE_BASE,
							new LanguageCompilerSpecPair(SCOM3_LANGUAGE_ID, SCOM3_COMPILER_ID), true));
				}
			}
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		api = new FlatProgramAPI(program, monitor);
		memory = program.getMemory();

		SCOM3Script script = new SCOM3Script(provider);

		List<SCOM3Section> sections = new ArrayList<SCOM3Section>();

		sections.add(new SCOM3Section(".data", script.getData(), true, false, false));
		sections.add(new SCOM3Section(".code", script.getCode(), true, false, true));
		sections.add(new SCOM3Section(".strings", script.getStrings(), true, false, false));
//		sections.add(new SCOM3Section(".fixups", script.getFixups(), true, false, false));
		sections.add(new SCOM3Section(".imports", script.getImports(), true, false, false));
//		sections.add(new SCOM3Section(".exports", script.getExports(), true, false, false));
//		sections.add(new SCOM3Section(".sections", script.getSections(), true, false, false));

		Address address = api.toAddr(loadSpec.getDesiredImageBase());
		for (int i = 0; i < sections.size(); ++i) {
			SCOM3Section section = sections.get(i);

			long length = section.getData().length;
			if (length > 0) {
				InputStream input = new ByteArrayInputStream(section.getData());

				try {
					memory.createInitializedBlock(section.getName(), address, input, length, monitor, false);
				} catch (LockException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (MemoryConflictException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (AddressOverflowException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (CancelledException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IllegalArgumentException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				long offset = NumericUtilities.getUnsignedAlignedValue(address.getOffset() + length, 16);
				address = api.toAddr(offset);
			}
		}

		// disassemble
		disassemble(program, monitor);

		// create functions
		try {
			createFunctions(program, monitor, script);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidInputException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// apply fixups
		try {
			applyFixups(program, monitor, script);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void disassemble(Program program, TaskMonitor monitor) {
		MemoryBlock codeBlock = program.getMemory().getBlock(".code");
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, DisassemblerMessageListener.CONSOLE);
		disassembler.disassemble(codeBlock.getStart(),
				new AddressSet(program, codeBlock.getStart(), codeBlock.getEnd()), false);
	}

	private void createFunctions(Program program, TaskMonitor monitor, SCOM3Script script)
			throws IOException, InvalidInputException {
		SymbolTable symtable = program.getSymbolTable();
		SCOM3Export[] exports = readExports(script);

		Address dataStart = memory.getBlock(".data").getStart();
		Address codeStart = memory.getBlock(".code").getStart();

		for (int i = 0; i < exports.length; ++i) {
			String name = exports[i].getName();
			byte type = exports[i].getType();
			int offset = exports[i].getOffset();

			if (type == SCOM3Export.DATA) {
				Address dataOffset = dataStart.add(offset);
				symtable.createLabel(dataOffset, name, SourceType.IMPORTED);
			} else if (type == SCOM3Export.FUNCTION) {
				Address codeOffset = codeStart.add(offset * 4);
				// TODO(adm244): use section name as namespace
				api.createFunction(codeOffset, name);
			}
		}
	}

	private void applyFixups(Program program, TaskMonitor monitor, SCOM3Script script) throws IOException, Exception {
		SCOM3Fixup[] fixups = readFixups(script);
		SCOM3Import[] imports = readImports(script);

		Address dataStart = memory.getBlock(".data").getStart();
		Address codeStart = memory.getBlock(".code").getStart();
		Address stringsStart = memory.getBlock(".strings").getStart();
		Address importsStart = memory.getBlock(".imports").getStart();

		for (int i = 0; i < fixups.length; ++i) {
			byte type = fixups[i].getType();
			int offset = fixups[i].getOffset();

			Address codeOffset = codeStart.add(offset * 4);
			Instruction instr = api.getInstructionContaining(codeOffset);
			int opindex = (int) ((codeOffset.getOffset() - instr.getAddress().getOffset()) / 4) - 1;
			int value = api.getInt(codeOffset);

			if (type == SCOM3Fixup.STRING) {
				Address stringsOffset = stringsStart.add(value);
				instr.addOperandReference(opindex, stringsOffset, RefType.READ, SourceType.IMPORTED);
				api.createAsciiString(stringsOffset);
			} else if (type == SCOM3Fixup.IMPORT) {
				Address importsOffset = importsStart.add(imports[value].getOffset());
				instr.addOperandReference(opindex, importsOffset, RefType.READ, SourceType.IMPORTED);
				api.createAsciiString(importsOffset);
			} else if (type == SCOM3Fixup.FUNCTION) {
//				setBackgroundColor(program, instr.getAddress(), Color.YELLOW);
				Address funcAddr = codeStart.add(value * 4);
				instr.addOperandReference(opindex, funcAddr, RefType.INDIRECTION, SourceType.IMPORTED);
			} else if (type == SCOM3Fixup.STACK) {
				// TODO(adm244): handle this case
				api.createBookmark(instr.getAddress(), "STACK", "STACK fixup detected");
				setBackgroundColor(program, instr.getAddress(), Color.RED);
			} else if (type == SCOM3Fixup.DATA) {
//				setBackgroundColor(program, instr.getAddress(), Color.YELLOW);
				Address dataOffset = dataStart.add(value);
				instr.addOperandReference(opindex, dataOffset, RefType.DATA, SourceType.IMPORTED);
				api.createData(dataOffset, DataType.DEFAULT);
			} else if (type == SCOM3Fixup.DATAPOINTER) {
				// TODO(adm244): handle this case
				api.createBookmark(instr.getAddress(), "DATAPOINTER", "DATAPOINTER fixup detected");
				setBackgroundColor(program, instr.getAddress(), Color.ORANGE);
			}

			// NOTE(adm244): jmp instructions: address(instr.next()) + (arg1 * 4)

			// TODO(adm244): implement DATAPOINTER and STACK fixup types
		}
	}

	private void setBackgroundColor(Program program, Address address, Color color) throws DuplicateNameException {
		IntRangeMap map = program.getIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
		if (map == null) {
			map = program.createIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
		}
		map.setValue(address, address, color.getRGB());
	}

	private SCOM3Fixup[] readFixups(SCOM3Script script) throws IOException {
		SCOM3Fixup[] fixups = new SCOM3Fixup[script.getFixupsCount()];

		InputStream input = new ByteArrayInputStream(script.getFixups());
		BinaryReader reader = new BinaryReader(new InputStreamByteProvider(input, script.getFixups().length), true);

		for (int i = 0; i < fixups.length; ++i) {
			fixups[i] = new SCOM3Fixup();
			fixups[i].setType(reader.readNextByte());
		}

		for (int i = 0; i < fixups.length; ++i) {
			fixups[i].setOffset(reader.readNextInt());
		}

		return fixups;
	}

	private SCOM3Import[] readImports(SCOM3Script script) throws IOException {
		SCOM3Import[] imports = new SCOM3Import[script.getImportsCount()];

		InputStream input = new ByteArrayInputStream(script.getImports());
		BinaryReader reader = new BinaryReader(new InputStreamByteProvider(input, script.getImports().length), true);

		for (int i = 0; i < imports.length; ++i) {
			long position = reader.getPointerIndex();
			String name = reader.readNextAsciiString();

			imports[i] = new SCOM3Import(name, position);
		}

		return imports;
	}

	private SCOM3Export[] readExports(SCOM3Script script) throws IOException {
		SCOM3Export[] exports = new SCOM3Export[script.getExportsCount()];

		InputStream input = new ByteArrayInputStream(script.getExports());
		BinaryReader reader = new BinaryReader(new InputStreamByteProvider(input, script.getExports().length), true);

		for (int i = 0; i < exports.length; ++i) {
			String name = reader.readNextAsciiString();
			int value = reader.readNextInt();

			byte type = (byte) (value >> 24);
			int offset = value & 0x00FFFFFF;

			exports[i] = new SCOM3Export(name, type, offset);
		}

		return exports;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		
		// TODO(adm244): add option to override IMAGE_BASE value
		// TODO(adm244): add option to include "fixups", "exports", "sections" memory blocks
//		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here. Not all options
		// require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}

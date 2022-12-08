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
import java.io.IOException;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.InputStreamByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.viewer.listingpanel.PropertyBasedBackgroundColorModel;
import ghidra.framework.options.Options;
import ghidra.program.database.IntRangeMap;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import reags.scom3.ScriptFixup;
import reags.scom3.ScriptImport;

/**
 * TODO: Provide class-level documentation that describes what this analyzer
 * does.
 */
public class ScriptFormatAnalyzer extends AbstractAnalyzer {

	private static final String PROCESSOR_NAME = "AGSVM";

	private static final String NAME = "Script format analyzer";
	private static final String DESCRIPTION = "Retrieves data from defined sections and applies it to program.";

	private FlatProgramAPI api;

	public ScriptFormatAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis(false);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		String executableFormat = program.getExecutableFormat();

		if (!executableFormat.equals(ScriptLoader.FORMAT_NAME)) {
			return false;
		}

		Language language = program.getLanguage();
		Processor processor = language.getProcessor();
		String processorName = processor.toString();

		if (!processorName.equals(PROCESSOR_NAME)) {
			return false;
		}

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null, "Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		api = new FlatProgramAPI(program, monitor);

//		try {
//			diassembleFunctions(program, monitor);
//			applyFixups(program, monitor);
//
//			return true;
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}

		return false;
	}

	private boolean diassembleFunctions(Program program, TaskMonitor monitor) {
		Memory memory = program.getMemory();

		MemoryBlock codeBlock = memory.getBlock(".code");
		AddressSetView addressSet = new AddressSet(program, codeBlock.getStart(), codeBlock.getEnd());
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, DisassemblerMessageListener.CONSOLE);

		FunctionIterator iterator = program.getFunctionManager().getFunctions(true);

		for (Function function : iterator) {
			Address entryPoint = function.getEntryPoint();
			disassembler.disassemble(entryPoint, addressSet, true);
		}

		return true;
	}

	private boolean applyFixups(Program program, TaskMonitor monitor) throws IOException, Exception {
		Memory memory = program.getMemory();

		MemoryBlock dataBlock = memory.getBlock(".data");
		MemoryBlock codeBlock = memory.getBlock(".code");
		MemoryBlock stringsBlock = memory.getBlock(".strings");
		MemoryBlock fixupsBlock = memory.getBlock(".fixups");
		MemoryBlock importsBlock = memory.getBlock(".imports");

		if (fixupsBlock == null) {
			return false;
		}
		
		ScriptFixup[] fixups = readFixups(fixupsBlock);
		ScriptImport[] imports = readImports(importsBlock);

		// FIXME(adm244): instead of calculating many offsets here, calculate them in
		// *.slaspec
		// e.g. ":jmp abs is opcode=??; arg1 [ abs = inst_next + arg1 * 4 ] { ... }"
		// this will output an absolute address for a jump instruction: "jmp 0x12345"

		// NOTE(adm244): jmp instructions: address(instr.next()) + (arg1 * 4)

		for (int i = 0; i < fixups.length; ++i) {
			byte type = fixups[i].getType();
			int offset = fixups[i].getOffset();

			Address codeOffset = codeBlock.getStart().add(offset * 4);
			Instruction instr = api.getInstructionContaining(codeOffset);
			int opindex = (int) ((codeOffset.getOffset() - instr.getAddress().getOffset()) / 4) - 1;
			int value = api.getInt(codeOffset);

			if (type == ScriptFixup.STRING && stringsBlock != null) {
				Address stringsOffset = stringsBlock.getStart().add(value);
				instr.addOperandReference(opindex, stringsOffset, RefType.READ, SourceType.IMPORTED);
				api.createAsciiString(stringsOffset);
			} else if (type == ScriptFixup.IMPORT && importsBlock != null) {
				Address importsOffset = importsBlock.getStart().add(imports[value].getOffset());
				instr.addOperandReference(opindex, importsOffset, RefType.READ, SourceType.IMPORTED);
				api.createAsciiString(importsOffset);
			} else if (type == ScriptFixup.FUNCTION) {
				setBackgroundColor(program, instr.getAddress(), Color.YELLOW);
//				Address funcAddr = codeBlock.getStart().add(value * 4);
//				instr.addOperandReference(opindex, funcAddr, RefType.INDIRECTION, SourceType.IMPORTED);
			} else if (type == ScriptFixup.STACK) {
				// TODO(adm244): handle this case
				api.createBookmark(instr.getAddress(), "STACK", "STACK fixup detected");
				setBackgroundColor(program, instr.getAddress(), Color.RED);
			} else if (type == ScriptFixup.DATA && dataBlock != null) {
//			setBackgroundColor(program, instr.getAddress(), Color.YELLOW);
				Address dataOffset = dataBlock.getStart().add(value);
				instr.addOperandReference(opindex, dataOffset, RefType.DATA, SourceType.IMPORTED);
				api.createData(dataOffset, DataType.DEFAULT);
			} else if (type == ScriptFixup.DATAPOINTER && dataBlock != null) {
				// TODO(adm244): handle this case
				api.createBookmark(instr.getAddress(), "DATAPOINTER", "DATAPOINTER fixup detected");
				setBackgroundColor(program, instr.getAddress(), Color.ORANGE);
			}

			// TODO(adm244): implement DATAPOINTER and STACK fixup types
		}

		return true;
	}

	private void setBackgroundColor(Program program, Address address, Color color) throws DuplicateNameException {
		IntRangeMap map = program.getIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
		if (map == null) {
			map = program.createIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
		}
		map.setValue(address, address, color.getRGB());
	}

	private ScriptFixup[] readFixups(MemoryBlock memoryBlock) throws IOException {
		ByteProvider provider = new InputStreamByteProvider(memoryBlock.getData(), memoryBlock.getSize());
		BinaryReader reader = new BinaryReader(provider, true);

		int count = reader.readNextInt();
		ScriptFixup[] fixups = new ScriptFixup[count];

		for (int i = 0; i < fixups.length; ++i) {
			fixups[i] = new ScriptFixup();
			fixups[i].setType(reader.readNextByte());
		}

		for (int i = 0; i < fixups.length; ++i) {
			fixups[i].setOffset(reader.readNextInt());
		}

		return fixups;
	}

	private ScriptImport[] readImports(MemoryBlock memoryBlock) throws IOException {
		ByteProvider provider = new InputStreamByteProvider(memoryBlock.getData(), memoryBlock.getSize());
		BinaryReader reader = new BinaryReader(provider, true);

		int count = reader.readNextInt();
		ScriptImport[] imports = new ScriptImport[count];

		for (int i = 0; i < imports.length; ++i) {
			long offset = reader.getPointerIndex();
			String name = reader.readNextAsciiString();

			imports[i] = new ScriptImport(name, offset);
		}

		return imports;
	}

}

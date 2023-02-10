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
package reags.analyzers;

import java.awt.Color;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

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
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import reags.ScriptLoader;
import reags.scom3.ScriptFixup;
import reags.scom3.ScriptImport;
import reags.state.ScriptAnalysisState;

/**
 * TODO: Provide class-level documentation that describes what this analyzer
 * does.
 */
public class ScriptFormatAnalyzer extends AbstractAnalyzer {

	private static final String PROCESSOR_NAME = "AGSVM";

	private static final String NAME = "Script format analyzer";
	private static final String DESCRIPTION = "Retrieves data from defined sections and applies it to program.";

	private FlatProgramAPI api;
	private Listing listing;
	private BasicBlockModel basicBlockModel;

	public ScriptFormatAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis(false);
//		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
		setPriority(AnalysisPriority.DISASSEMBLY.after());
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
		listing = program.getListing();
		basicBlockModel = new BasicBlockModel(program);

		try {
			applyFixups(program, monitor);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return true;

//		AddressSpace constSpace = program.getAddressFactory().getConstantSpace();
//		
//		ScriptAnalysisState analysisState = getScriptAnalysisState(program);
//		for (Entry<Address, Integer> entry : analysisState.fixups.entrySet()) {
//			Address address = entry.getKey();
//			int type = entry.getValue();
//
//			switch (type) {
//			case ScriptFixup.STRING:
//				Instruction instr = api.getInstructionContaining(address);
//				PcodeOp[] ops = instr.getPcode();
//				
//				if (ops.length == 1) {
//					ops[0].setOpcode(PcodeOp.CPOOLREF);
//					Varnode offsetNode = ops[0].getInput(0);
//					Varnode zero = new Varnode(constSpace.getAddress(0), 4);
//					Varnode cpoolString = new Varnode(constSpace.getAddress(244), 4);
//					
//					ops[0].removeInput(0);
//					
//					ops[0].insertInput(zero, 0);
//					ops[0].insertInput(offsetNode, 1);
//					ops[0].insertInput(cpoolString, 2);
//				}
//				
//				break;
//			}
//		}

//		BookmarkManager bookmarkManager = program.getBookmarkManager();
//
//		// NOTE(adm244): this creates memory references for imported data/functions
//		Iterator<Bookmark> it = bookmarkManager.getBookmarksIterator(BookmarkType.INFO);
//		while (it.hasNext()) {
//			Bookmark bookmark = it.next();
//			if (bookmark.getCategory().equals("IMPORT")) {
//				Address bookmarkAddress = bookmark.getAddress();
//
//				Instruction instr = api.getInstructionContaining(bookmarkAddress);
//				int opIndex = (int) (bookmarkAddress.subtract(instr.getAddress()) / 4 - 1);
//
//				try {
//					Address refAddress = api.toAddr((long) api.getInt(bookmarkAddress));
//					instr.addOperandReference(opIndex, refAddress, RefType.DATA, SourceType.ANALYSIS);
//					bookmarkManager.removeBookmark(bookmark);
//				} catch (Exception e) {
//					// TODO: handle exception
//					e.printStackTrace();
//				}
//			}
//		}

		// TODO(adm244): set appropriate calling-conventions to functions;
		// we have 4: nearcall, nearcallas, farcall, farcallas:
		// nearcall == stdcall
		// nearcallas == stdcall + thiscall
		// farcall == cdecl
		// farcallas == cdecl + thiscall

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

//		return false;
	}

//	private boolean diassembleFunctions(Program program, TaskMonitor monitor) {
//		Memory memory = program.getMemory();
//
//		MemoryBlock codeBlock = memory.getBlock(".code");
//		AddressSetView addressSet = new AddressSet(program, codeBlock.getStart(), codeBlock.getEnd());
//		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, DisassemblerMessageListener.CONSOLE);
//
//		FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
//
//		for (Function function : iterator) {
//			Address entryPoint = function.getEntryPoint();
//			disassembler.disassemble(entryPoint, addressSet, true);
//		}
//
//		return true;
//	}

	private ImportType analyzeImportType(Instruction entry, TaskMonitor monitor) {
		// TODO(adm244): analyze import type
		try {
			// TODO(adm244): track multiple result objects (if any)
//			List<Object> trackingObjects = new ArrayList<Object>();
//			Collections.addAll(trackingObjects, entry.getResultObjects());
			Object trackingObject = entry.getResultObjects()[0];

			CodeBlock entryBlock = basicBlockModel.getFirstCodeBlockContaining(entry.getAddress(), monitor);
			AddressSetView addressRange = new AddressSet(entry.getNext().getAddress(), entryBlock.getMaxAddress());

			// TODO(adm244): analyze multiple basic blocks

			InstructionIterator instrIter = listing.getInstructions(addressRange, true);
			while (instrIter.hasNext()) {
				Instruction instr = instrIter.next();

				Object[] inputObjects = instr.getInputObjects();
				for (int i = 0; i < inputObjects.length; ++i) {
					if (inputObjects[i].equals(trackingObject)) {
						String mnemonic = instr.getMnemonicString();
						if (mnemonic.equals("farcall")) {
							return ImportType.FUNCTION;
						}
					}
				}

				Object[] outputObjects = instr.getResultObjects();
				if (outputObjects.length == 0) {
					continue;
				}

				Object resultObject = outputObjects[0];
				if (trackingObject.equals(resultObject)) {
					break;
				}
			}
		} catch (CancelledException e) {
			e.printStackTrace();
		}

		return ImportType.DATA;
	}

	private boolean applyFixups(Program program, TaskMonitor monitor) throws IOException, Exception {
		Memory memory = program.getMemory();

		MemoryBlock dataBlock = memory.getBlock("data");
		MemoryBlock codeBlock = memory.getBlock("code");
		MemoryBlock stringsBlock = memory.getBlock("strings");
		MemoryBlock fixupsBlock = memory.getBlock("fixups");
		MemoryBlock importsBlock = memory.getBlock("imports");

		if (fixupsBlock == null) {
			return false;
		}

		ScriptFixup[] fixups = readFixups(fixupsBlock);
		ScriptImport[] imports = readImports(importsBlock);

		ScriptAnalysisState state = ScriptAnalysisState.getState(program);
		HashMap<Long, ImportType> importTypeCache = new HashMap<Long, ImportType>();

		// FIXME(adm244): instead of calculating many offsets here, calculate them in
		// *.slaspec
		// e.g. ":jmp abs is opcode=??; arg1 [ abs = inst_next + arg1 * 4 ] { ... }"
		// this will output an absolute address for a jump instruction: "jmp 0x12345"

		// NOTE(adm244): jmp instructions: address(instr.next()) + (arg1 * 4)

//		AddressSpace constSpace = program.getAddressFactory().getConstantSpace();

		long lastBlockOffset = memory.getMaxAddress().getUnsignedOffset();
		long externalBlockOffset = NumericUtilities.getUnsignedAlignedValue(lastBlockOffset + 1, 16);

		Address externalBlockBase = api.toAddr(externalBlockOffset);
		ExternalManager externalManager = api.getCurrentProgram().getExternalManager();

		Map<String, Address> externals = new HashMap<String, Address>();
		int entrySize = 4; // 32768

		for (int i = 0; i < fixups.length; ++i) {
			byte type = fixups[i].getType();
			int offset = fixups[i].getOffset();

			Address codeOffset = codeBlock.getStart().add(offset * 4);
			Instruction instr = api.getInstructionContaining(codeOffset);
			int opindex = (int) ((codeOffset.getOffset() - instr.getAddress().getOffset()) / 4) - 1;
			long value = api.getInt(codeOffset);

			FixupType fixupType = FixupType.UNDEFINED;

			if (type == ScriptFixup.STRING && stringsBlock != null) {
				Address stringsOffset = stringsBlock.getStart().add(value);

				Data stringData = api.createAsciiString(stringsOffset);
				state.strings.put(value, (String) stringData.getValue());

				fixupType = FixupType.STRING;

				instr.addOperandReference(opindex, stringsOffset, RefType.READ, SourceType.ANALYSIS);
			}

			else if (type == ScriptFixup.IMPORT && importsBlock != null) {
				Address importsOffset = importsBlock.getStart().add(imports[(int) value].getOffset());

				Data importData = api.createAsciiString(importsOffset);
				state.imports.put(value, (String) importData.getValue());

				ImportType importType;

				if (importTypeCache.containsKey(value)) {
					importType = importTypeCache.get(value);
				} else {
					importType = analyzeImportType(instr, monitor);
					importTypeCache.put(value, importType);
				}

				if (importType == ImportType.FUNCTION) {
					fixupType = FixupType.IMPORT_FUNCTION;

					Address externalAddress = externalBlockBase.add(externals.size() * 4);
					String importName = imports[(int) value].getName();
					if (externals.containsKey(importName)) {
						externalAddress = externals.get(importName);
					} else {
						externals.put(importName, externalAddress);
					}

					if (!state.functions.containsKey(value)) {
						state.functions.put(value, externalAddress);
					}

					instr.addOperandReference(opindex, externalAddress, RefType.INDIRECTION, SourceType.ANALYSIS);
				} else {
					fixupType = FixupType.IMPORT_DATA;
					instr.addOperandReference(opindex, importsOffset, RefType.READ, SourceType.ANALYSIS);
				}
			}

			else if (type == ScriptFixup.FUNCTION) {
				// TODO(adm244): extract address calculations into separate static class, so all
				// calculations are done in single place
				Address funcAddr = codeBlock.getStart().add(value * entrySize);

				fixupType = FixupType.FUNCTION;

				instr.addOperandReference(opindex, funcAddr, RefType.INDIRECTION, SourceType.ANALYSIS);
			}

			else if (type == ScriptFixup.DATA && dataBlock != null) {
				Address dataOffset = dataBlock.getStart().add(value);
				api.createData(dataOffset, DataType.DEFAULT);

				fixupType = FixupType.DATA;

				instr.addOperandReference(opindex, dataOffset, RefType.DATA, SourceType.ANALYSIS);
			}

			// TODO(adm244): implement DATAPOINTER and STACK fixup types

			// TODO(adm244): NOT IMPLEMENTED
			else if (type == ScriptFixup.DATAPOINTER && dataBlock != null) {
				// TODO(adm244): handle this case
				fixupType = FixupType.DATAPOINTER;

				api.createBookmark(instr.getAddress(), "DATAPOINTER", "DATAPOINTER fixup detected");
				setBackgroundColor(program, instr.getAddress(), Color.ORANGE);
			}

			// TODO(adm244): NOT IMPLEMENTED
			else if (type == ScriptFixup.STACK) {
				// TODO(adm244): handle this case
				fixupType = FixupType.STACK;

				api.createBookmark(instr.getAddress(), "STACK", "STACK fixup detected");
				setBackgroundColor(program, instr.getAddress(), Color.RED);
			}

			if (fixupType != FixupType.UNDEFINED) {
				state.fixups.put(instr.getAddress(), fixupType);
			} else {
				api.createBookmark(instr.getAddress(), "Fixup error", "Undefined fixup type");
				setBackgroundColor(program, instr.getAddress(), Color.RED);
			}
		}

		long externalBlockSize = externals.size() * entrySize;
		memory.createUninitializedBlock("_external", externalBlockBase, externalBlockSize, false);

		for (Entry<Long, Address> funcSet : state.functions.entrySet()) {
			Address addr = funcSet.getValue();
			String name = state.imports.get(funcSet.getKey());

			Function externalFunction = api.createFunction(addr, name);
			if (externalFunction != null) {
				ExternalLocation externalLocation = externalManager.addExtFunction(Library.UNKNOWN, name, null,
						SourceType.ANALYSIS);

				externalFunction.setThunkedFunction(externalLocation.getFunction());
				externalFunction.setCallingConvention("farcall");
			}
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

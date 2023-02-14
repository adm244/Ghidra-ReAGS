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
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import reags.scom3.Script;
import reags.scom3.ScriptExport;
import reags.scom3.ScriptMemoryBlock;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class ScriptLoader extends AbstractProgramWrapperLoader {

	public static final String FORMAT_NAME = "Adventure Game Studio compiled script (scom3)";

	public static final String IMPORT_PROPERTIES = "ImportProperties";

	private static final String SCOM3_LANGUAGE_ID = "AGSVM:LE:32:default";
	private static final String SCOM3_COMPILER_ID = "default";
	private static final long IMAGE_BASE = 0x100000;

//	public static int importMaxSize = 32768;

	/*
	 * TODO: DO THIS FIRST: figure out in the analyzer what is an imported function,
	 * the rest is the data. Create a memory block for imported functions only and
	 * mark it as external (code is below). Then change all imports addresses
	 * separating data and functions into two groups. We know sizes of functions and
	 * this should be easy, but for data it will overlap... I guess that's fine?
	 * 
	 * Use CODE_ANALYSIS priority to analyze farcall instructions and separate it
	 * from data imports.
	 * 
	 * THEN figure out data imports sizes by:
	 * 
	 * a) matching against known named imports (things like player, character,
	 * object, game, etc.)
	 * 
	 * b) analyzing usage of unmatched data (may be incorrect, but it's the best
	 * we've got here)
	 * 
	 * AND create an "_external" memory block that will hold all imports.
	 * 
	 * AFTER that mark every imported function as a thunk call to external memory
	 * AND create all data types.
	 * 
	 * This SHOULD get us to the point when we can care about things like analyzing
	 * function prototypes, demangling function names, etc.
	 */

	@Override
	public String getName() {
		return FORMAT_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (Script.isValid(provider)) {
			LanguageCompilerSpecPair languageCompilerSpecPair = new LanguageCompilerSpecPair(SCOM3_LANGUAGE_ID,
					SCOM3_COMPILER_ID);
			LoadSpec loadSpec = new LoadSpec(this, IMAGE_BASE, languageCompilerSpecPair, true);

			loadSpecs.add(loadSpec);
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		Memory memory = program.getMemory();

		try {
			// STEP 0. Load and parse script file
			Script script = new Script(provider);

			// STEP 1. Create flat memory blocks for each script section in a file
			createMemoryBlocks(api, script, loadSpec.getDesiredImageBase());

			// STEP 2. Modify code section such that all offsets outside are absolute
//			applyFixups(api, memory, script, monitor);

			// STEP 3. Mark all exported data and functions with their names
			createExports(api, memory, script);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void createMemoryBlocks(FlatProgramAPI api, Script script, long imageBase) throws Exception {
		List<ScriptMemoryBlock> sections = new ArrayList<ScriptMemoryBlock>();

		sections.add(new ScriptMemoryBlock("data", script.getData(), true, true, false));
		// FIXME(adm244): create memory block for each script section instead of single
		// code block
		sections.add(new ScriptMemoryBlock("code", script.getCode(), true, false, true));
		sections.add(new ScriptMemoryBlock("strings", script.getStrings(), true, false, false));
		sections.add(new ScriptMemoryBlock("fixups", script.getFixups(), true, false, false));
		sections.add(new ScriptMemoryBlock("imports", script.getImports(), true, false, false));
		sections.add(new ScriptMemoryBlock("exports", script.getExports(), true, false, false));
		sections.add(new ScriptMemoryBlock("sections", script.getSections(), true, false, false));

		Address address = api.toAddr(imageBase);

		for (int i = 0; i < sections.size(); ++i) {
			ScriptMemoryBlock section = sections.get(i);

			String name = section.getName();
			byte[] data = section.getData();
			boolean canRead = section.getCanRead();
			boolean canWrite = section.getCanWrite();
			boolean canExecute = section.getCanExecute();

			if (data != null && data.length > 0) {
				MemoryBlock memoryBlock = api.createMemoryBlock(name, address, data, false);
				memoryBlock.setPermissions(canRead, canWrite, canExecute);
				memoryBlock.setSourceName("Script loader");

				long offset = address.add(data.length).getUnsignedOffset();
				long alignedOffset = NumericUtilities.getUnsignedAlignedValue(offset, 16);
				address = api.toAddr(alignedOffset);
			}
		}
	}

//	private void applyFixups(FlatProgramAPI api, Memory memory, Script script, TaskMonitor monitor) throws Exception {
//		MemoryBlock fixupsBlock = memory.getBlock("fixups");
//		if (fixupsBlock == null) {
//			return;
//		}
//
//		MemoryBlock dataBlock = memory.getBlock("data");
//		MemoryBlock codeBlock = memory.getBlock("code");
//		MemoryBlock stringsBlock = memory.getBlock("strings");
//		MemoryBlock importsBlock = memory.getBlock("imports");
//
//		ScriptFixup[] fixups = readFixups(fixupsBlock);
//		ScriptImport[] imports = readImports(importsBlock);
//
//		long lastBlockOffset = memory.getMaxAddress().getUnsignedOffset();
//		long externalBlockOffset = NumericUtilities.getUnsignedAlignedValue(lastBlockOffset + 1, 16);
//
//		Address externalBlockBase = api.toAddr(externalBlockOffset);
////		Address externalBlockBase = AddressSpace.EXTERNAL_SPACE.getAddress(0);
//
//		Map<String, Address> externals = new HashMap<String, Address>();
//		Program program = api.getCurrentProgram();
//
//		// FIXME(adm244): use AnalysisStateInfo to store information across analyzers
//		PropertyMapManager propertiesManager = program.getUsrPropertyManager();
//		ObjectPropertyMap<ImportProperty> importProperties = propertiesManager
//				.createObjectPropertyMap(IMPORT_PROPERTIES, ImportProperty.class);
//
//		// NOTE(adm244): since we don't know data sizes (except when it's a function
//		// which can be just thunked) we use some magic number for all entries so they
//		// won't (mostly) overlap each other. Maybe a better solution would be matching
//		// imports name against a predefined set to figure out it's size first and then
//		// analyze data usage to guess all user-defined data sizes...
//		int entrySize = 32768;
//
//		/*
//		 * These are reserved script names according to classic compilers source:
//		 * "inventory", "character", "views", "player", "object", "mouse", "system",
//		 * "game", "palette", "hotspot", "region", "dialog", "gui", "GUI"
//		 */
//
////		ScriptAnalysisState analysisState = getScriptAnalysisState(program);
//
//		for (int i = 0; i < fixups.length; ++i) {
//			byte type = fixups[i].getType();
//			int offset = fixups[i].getOffset();
//
//			Address codeOffset = codeBlock.getStart().add(offset * 4);
//			int value = api.getInt(codeOffset);
//
//			Address address = api.toAddr(value);
//
////			analysisState.fixups.put(codeOffset, (int) type);
//
//			if (type == ScriptFixup.STRING) {
//				address = stringsBlock.getStart().add(value);
//				api.createBookmark(codeOffset, "STRING", String.format("%x", value));
//			}
//
//			else if (type == ScriptFixup.IMPORT) {
//				String importName = imports[value].getName();
//
////				Address externalAddress = externalBlockBase.add(value * importMaxSize);
//
//				// NOTE(adm244): this will be replaced at the later stage
////				address = Address.NO_ADDRESS;
////
//				Address externalAddress = externalBlockBase.add(externals.size() * entrySize);
//
//				importProperties.add(codeOffset, new ImportProperty(address.getOffset(), importName));
////
//				if (externals.containsKey(importName)) {
//					externalAddress = externals.get(importName);
//				} else {
//					externals.put(importName, externalAddress);
//				}
////
//				address = externalAddress;
////
////				api.getCurrentProgram().getBookmarkManager().setBookmark(codeOffset, BookmarkType.INFO, "IMPORT",
////						String.format("%x", value));
////
//////				api.createBookmark(codeOffset, "IMPORT", String.format("%x", value));
//////				setBackgroundColor(api, codeOffset, Color.YELLOW);
//			}
//
//			else if (type == ScriptFixup.FUNCTION) {
//				address = codeBlock.getStart().add(value * 4);
//			}
//
//			else if (type == ScriptFixup.DATA) {
//				address = dataBlock.getStart().add(value);
//			}
//
//			else if (type == ScriptFixup.DATAPOINTER) {
//				// TODO(adm244): handle this case
//				api.createBookmark(codeOffset, "DATAPOINTER", "DATAPOINTER fixup detected");
//				setBackgroundColor(api, codeOffset, Color.ORANGE);
//			}
//
//			else if (type == ScriptFixup.STACK) {
//				// TODO(adm244): handle this case
//				api.createBookmark(codeOffset, "STACK", "STACK fixup detected");
//				setBackgroundColor(api, codeOffset, Color.RED);
//			}
//
////			api.setInt(codeOffset, (int) address.getOffset());
//		}
//
//		long externalBlockSize = externals.size() * entrySize;
////		AddressSpace addrSpace = AddressSpace.EXTERNAL_SPACE;
////		addrSpace.getAddress(externalBlockSize);
//
////		memory.createUninitializedBlock("_external", externalBlockBase, externalBlockSize, false);
////		memory.createInitializedBlock("_external", externalBlockBase, externalBlockSize, (byte) 0xFF, monitor, false);
////
//		ExternalManager externalManager = api.getCurrentProgram().getExternalManager();
//
//		for (Entry<String, Address> external : externals.entrySet()) {
//			Address externalAddress = external.getValue();
//			String externalName = external.getKey();
//
//			// NOTE(adm244): this just adds named locations into IMPORTS folder
////			externalManager.addExtLocation(Library.UNKNOWN, externalName, null, SourceType.IMPORTED);
////
////			api.createLabel(externalAddress, externalName, true, SourceType.IMPORTED);
//
//			/*
//			 * TODO: Mark all functions called with farcall as external (code is below)
//			 */
//
//			// TODO(adm244): move this into analyzer, I guess...
////			Function externalFunction = api.createFunction(externalAddress, externalName);
////			ExternalLocation externalLocation = externalManager.addExtFunction(Library.UNKNOWN, externalName, null,
////					SourceType.IMPORTED);
////
////			externalFunction.setThunkedFunction(externalLocation.getFunction());
//
//			// NOTE(adm244): external entry point means that this address is exported !!!
////			api.getCurrentProgram().getSymbolTable().addExternalEntryPoint(externalAddress);
//		}
//	}

	// FIXME(adm244): move to utils
//	private void setBackgroundColor(FlatProgramAPI api, Address address, Color color) {
//		Program program = api.getCurrentProgram();
//
//		IntRangeMap map = program.getIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
//		if (map == null) {
//			try {
//				map = program.createIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
//			} catch (DuplicateNameException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//		}
//		map.setValue(address, address, color.getRGB());
//	}

	private void createExports(FlatProgramAPI api, Memory memory, Script script) throws IOException, Exception {
		SymbolTable symbolTable = api.getCurrentProgram().getSymbolTable();
		ScriptExport[] exports = readExports(script);

		MemoryBlock dataBlock = memory.getBlock("data");
		MemoryBlock codeBlock = memory.getBlock("code");

		for (int i = 0; i < exports.length; ++i) {
			String name = exports[i].getName();
			byte type = exports[i].getType();
			int offset = exports[i].getOffset();

			if (type == ScriptExport.DATA && dataBlock != null) {
				Address dataOffset = dataBlock.getStart().add(offset);
				api.createLabel(dataOffset, name, true, SourceType.IMPORTED);

				symbolTable.addExternalEntryPoint(dataOffset);
			} else if (type == ScriptExport.FUNCTION) {
				Address codeOffset = codeBlock.getStart().add(offset * 4);
				api.createFunction(codeOffset, name);

				// add this to EXPORTS list
				symbolTable.addExternalEntryPoint(codeOffset);
			}
		}
	}

	// TODO(adm244): read this inside Script object instead
//	private ScriptFixup[] readFixups(MemoryBlock memoryBlock) throws IOException {
//		ByteProvider provider = new InputStreamByteProvider(memoryBlock.getData(), memoryBlock.getSize());
//		BinaryReader reader = new BinaryReader(provider, true);
//
//		int count = reader.readNextInt();
//		ScriptFixup[] fixups = new ScriptFixup[count];
//
//		for (int i = 0; i < fixups.length; ++i) {
//			fixups[i] = new ScriptFixup();
//			fixups[i].setType(reader.readNextByte());
//		}
//
//		for (int i = 0; i < fixups.length; ++i) {
//			fixups[i].setOffset(reader.readNextInt());
//		}
//
//		return fixups;
//	}
//
//	// TODO(adm244): read this inside Script object instead
//	private ScriptImport[] readImports(MemoryBlock memoryBlock) throws IOException {
//		ByteProvider provider = new InputStreamByteProvider(memoryBlock.getData(), memoryBlock.getSize());
//		BinaryReader reader = new BinaryReader(provider, true);
//
//		int count = reader.readNextInt();
//		ScriptImport[] imports = new ScriptImport[count];
//
//		for (int i = 0; i < imports.length; ++i) {
//			long offset = reader.getPointerIndex();
//			String name = reader.readNextAsciiString();
//
//			imports[i] = new ScriptImport(name, offset);
//		}
//
//		return imports;
//	}

	// TODO(adm244): read this inside Script object instead
	private ScriptExport[] readExports(Script script) throws IOException {
		InputStream input = new ByteArrayInputStream(script.getExports());
		BinaryReader reader = new BinaryReader(new InputStreamByteProvider(input, script.getExports().length), true);

		int count = reader.readNextInt();
		ScriptExport[] exports = new ScriptExport[count];

		for (int i = 0; i < exports.length; ++i) {
			String name = reader.readNextAsciiString();
			int value = reader.readNextInt();

			byte type = (byte) (value >> 24);
			int offset = value & 0x00FFFFFF;

			exports[i] = new ScriptExport(name, type, offset);
		}

		return exports;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'

		// TODO(adm244): add option to override IMAGE_BASE value
		// TODO(adm244): add option to include "fixups", "exports", "sections" memory
		// blocks
		// TODO(adm244): add option "restrict disassembly to ".code" section"
		// this is in case there is (somehow) a code in other sections (like ".data")

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

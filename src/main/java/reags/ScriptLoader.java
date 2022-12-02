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

	private static final String SCOM3_LANGUAGE_ID = "AGSVM:LE:32:default";
	private static final String SCOM3_COMPILER_ID = "default";
	private static final long IMAGE_BASE = 0x100000;

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
			Script script = new Script(provider);

			// FIXME(adm244): maybe we should only create memory blocks in the loader...
			// TODO(adm244): create segments (as namespaces probably)

			createMemoryBlocks(api, script, loadSpec.getDesiredImageBase());
			createExports(api, memory, script);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void createMemoryBlocks(FlatProgramAPI api, Script script, long imageBase) throws Exception {
		List<ScriptMemoryBlock> sections = new ArrayList<ScriptMemoryBlock>();

		sections.add(new ScriptMemoryBlock(".data", script.getData(), true, false, false));
		sections.add(new ScriptMemoryBlock(".code", script.getCode(), true, false, true));
		sections.add(new ScriptMemoryBlock(".strings", script.getStrings(), true, false, false));
		sections.add(new ScriptMemoryBlock(".fixups", script.getFixups(), true, false, false));
		sections.add(new ScriptMemoryBlock(".imports", script.getImports(), true, false, false));
		sections.add(new ScriptMemoryBlock(".exports", script.getExports(), true, false, false));
		sections.add(new ScriptMemoryBlock(".sections", script.getSections(), true, false, false));

		Address address = api.toAddr(imageBase);

		for (int i = 0; i < sections.size(); ++i) {
			ScriptMemoryBlock section = sections.get(i);

			String name = section.getName();
			byte[] data = section.getData();
			boolean canRead = section.getCanRead();
			boolean canWrite = section.getCanWrite();
			boolean canExecute = section.getCanExecute();

			if (data.length > 0) {
				MemoryBlock memoryBlock = api.createMemoryBlock(name, address, data, false);
				memoryBlock.setPermissions(canRead, canWrite, canExecute);

				long offset = address.add(data.length).getOffset();
				long alignedOffset = NumericUtilities.getUnsignedAlignedValue(offset, 16);
				address = api.toAddr(alignedOffset);
			}
		}
	}

	private void createExports(FlatProgramAPI api, Memory memory, Script script) throws IOException, Exception {
		ScriptExport[] exports = readExports(script);

		Address dataStart = memory.getBlock(".data").getStart();
		Address codeStart = memory.getBlock(".code").getStart();

		for (int i = 0; i < exports.length; ++i) {
			String name = exports[i].getName();
			byte type = exports[i].getType();
			int offset = exports[i].getOffset();

			if (type == ScriptExport.DATA) {
				Address dataOffset = dataStart.add(offset);
				api.createLabel(dataOffset, name, true, SourceType.IMPORTED);
			} else if (type == ScriptExport.FUNCTION) {
				Address codeOffset = codeStart.add(offset * 4);
				// TODO(adm244): use section name as namespace
				api.createFunction(codeOffset, name);
			}
		}
	}

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

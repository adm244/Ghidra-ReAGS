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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ParserContext;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.Saveable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import reags.properties.ImportProperty;
import reags.properties.ImportType;

public class ScriptImportsAnalyzer extends AbstractAnalyzer {

	private static final String PROCESSOR_NAME = "AGSVM";

	private static final String NAME = "Script imports analyzer";
	private static final String DESCRIPTION = "Analyzes usage of imports and determines their types.";

	public ScriptImportsAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis(false);
		setPriority(AnalysisPriority.CODE_ANALYSIS);
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
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		FlatProgramAPI api = new FlatProgramAPI(program);

		PropertyMapManager propertiesManager = program.getUsrPropertyManager();
		ObjectPropertyMap<? extends Saveable> importProperties = propertiesManager
				.getObjectPropertyMap(ScriptLoader.IMPORT_PROPERTIES);

		Listing listing = program.getListing();

		AddressIterator iter = importProperties.getPropertyIterator(set);
		while (iter.hasNext()) {
			Address address = iter.next();
			ImportProperty importProperty = (ImportProperty) importProperties.get(address);

			/*
			 * Imported function is never called directly. "farcall" instruction is an
			 * indirect call.
			 */

			ImportType type = importProperty.getType();

			Instruction instr = listing.getInstructionContaining(address);
			try {
				InstructionContext instrContext = instr.getInstructionContext();
				ParserContext parserContext = instrContext.getParserContext();
				InstructionPrototype prototype = parserContext.getPrototype();

				Object[] resultObjects = prototype.getResultObjects(instrContext);

				// NOTE(adm244): should be only one output
				if (resultObjects.length > 1) {
					continue;
				}

				// NOTE(adm244): only track registers
				if (resultObjects[0].getClass() != Register.class) {
					continue;
				}

				Register destRegister = (Register) resultObjects[0];
				type = analyzeImportType(instr.getNext(), destRegister);
			} catch (MemoryAccessException ex) {
				ex.printStackTrace();
			}

			importProperty.setType(type);

			String importName = importProperty.getName();
			ImportType importType = importProperty.getType();

//			log.appendMsg(
//					String.format("0x%X: %s, type = %s\n", address.getOffset(), importName, importType.toString()));

			program.getBookmarkManager().setBookmark(address, BookmarkType.ANALYSIS, importType.toString(), importName);
		}

		return true;
	}

	private ImportType analyzeImportType(Instruction instr, Register traceRegister) throws MemoryAccessException {
		if (instr == null) {
			// FIXME(adm244): this shouldn't happen, limit analysis to a function scope
			return ImportType.DATA;
		}

		InstructionContext context = instr.getInstructionContext();
		ParserContext parserContext = context.getParserContext();
		InstructionPrototype prototype = parserContext.getPrototype();

		Object[] inputs = prototype.getInputObjects(context);
		Object[] outputs = prototype.getResultObjects(context);

		boolean inputsMatch = contains(inputs, traceRegister);
		boolean outputsMatch = contains(outputs, traceRegister);

		// traced register is used as an input into this instruction
		if (inputsMatch && !outputsMatch) {
			FlowType flowType = prototype.getFlowType(context);
			boolean isFarcall = instr.getMnemonicString().equals("farcall");

			// check if it's a "farcall" instruction
			if (flowType.isCall() && isFarcall) {
				return ImportType.FUNCTION;
			}

			// TODO(adm244): at this point we have to trace more than one register
			// ignore this case for now...
		}

		// traced register is used as an output of this instruction
		else if (!inputsMatch && outputsMatch) {
			// this is the end of a traced register life, assume import is data
			return ImportType.DATA;
		}

		// at this point traced register is either the same or unused

		// skip to the next instruction
		return analyzeImportType(instr.getNext(), traceRegister);
	}

	private boolean contains(Object[] arr, Object obj) {
		for (int i = 0; i < arr.length; ++i) {
			if (arr[i].equals(obj)) {
				return true;
			}
		}

		return false;
	}

}

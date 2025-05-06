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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.util.Saveable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import reags.ScriptLoader;
import reags.properties.ImportProperty;
import reags.properties.ImportType;

public class ScriptImportsAnalyzer extends AbstractAnalyzer {

	private static final String PROCESSOR_NAME = "AGSVM";

	/*
	 * TODO(adm244): implement a custom pcode op for 'farcall' instruction that will
	 * be used to inject a custom pcode that will take arguments from 'farstack' and
	 * put them onto real stack and make a standard call, then it will purge the
	 * stack to get it back to original state.
	 * 
	 * This way we separate 'farcall' stack from our real stack using the real stack
	 * (since we cannot create more than one stack in processor specs).
	 */

	/*
	 * NOTE(adm244): "cpool" pcode can be described by extending ConstantPool class.
	 */

	/*
	 * TODO(adm244): write a full function analyzer using a pcode emulator to guess
	 * imports types and sizes, also function prototypes, etc.
	 * 
	 * We need to trace registers that hold imports and analyze reads, writes and
	 * accesses to these imports. This will allow us to determine import type and
	 * its size (only for portion that is actually accessed in code). It would also
	 * help to recover function prototypes for near and far calls (op calls too).
	 * 
	 * Maybe we should split analyzers that will analyze instructions separately and
	 * will have their own "state". We would only have a basic analyzing function
	 * that emulates instructions and calls all analyzers to decide what to do with
	 * this information...
	 */

	// TODO(adm244): rename this to function analyzer
	private static final String NAME = "Scom3 Function Analyzer";
	private static final String DESCRIPTION = "Performs functions analysis with different analyzers.";

	private ObjectPropertyMap<? extends Saveable> importProperties;
//	private HashMap<String, ImportProperty> importPropertiesMap;

	public ScriptImportsAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis(false);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
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

//		Listing listing = program.getListing();
//		FunctionManager functionManager = program.getFunctionManager();
//
//		FunctionIterator iter = functionManager.getFunctions(set, true);
//		while (iter.hasNext()) {
//			Function func = iter.next();
//
//			long farStackSize = 0;
//
//			try {
//				InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
//				while (instrIter.hasNext()) {
//					Instruction instr = instrIter.next();
//
//					String mnemonic = instr.getMnemonicString();
//					int opCount = instr.getNumOperands();
//					Address addr = instr.;
//
//					switch (mnemonic) {
//					case "farpush":
//						++farStackSize;
//						break;
//
//					case "farsubsp":
//						farStackSize -= api.getInt(addr);
//						if (farStackSize < 0) {
//							throw new Exception("Far stack underflow!");
//						}
//						break;
//
//					case "stackptr":
//						long oldValue = api.getInt(addr);
//						long value = oldValue + farStackSize;
//						api.setInt(instr.getAddress(0), (int) value);
//						break;
//
//					default:
//						break;
//					}
//				}
//			} catch (Exception e) {
//				e.printStackTrace();
//			}
//		}

//		PropertyMapManager propertiesManager = program.getUsrPropertyManager();
//		importProperties = propertiesManager.getObjectPropertyMap(ScriptLoader.IMPORT_PROPERTIES);

		// STEP 1. (DONE) Figure out import type (data or function)
//		analyzeImportTypes(program, set, monitor, log);

		/*
		 * TODO(adm244):
		 * 
		 * 1) set base address for each import
		 * 
		 * 2) decompile containing function and iterate over global symbols
		 * 
		 * 3) for each global symbol get a node that creates it and get an import using
		 * it's name
		 * 
		 * 4) calculate offset between import base and accessed symbol address
		 * 
		 * 5) if offset is bigger than current import size then change its size to be
		 * offset + 4
		 */

//		ExternalManager externalManager = api.getCurrentProgram().getExternalManager();
//
//		AddressIterator iter = importProperties.getPropertyIterator();
//		while (iter.hasNext()) {
//			Address address = iter.next();
//
//			ImportProperty prop = (ImportProperty) importProperties.get(address);
//			Address addr = api.toAddr(prop.getBaseOffset());
//			String name = prop.getName();
//			ImportType type = prop.getType();
//
//			try {
////				if (type == ImportType.FUNCTION) {
////					Function externalFunction = api.createFunction(addr, name);
////					ExternalLocation externalLocation = externalManager.addExtFunction(Library.UNKNOWN, name, null,
////							SourceType.IMPORTED);
////
////					externalFunction.setThunkedFunction(externalLocation.getFunction());
////				} else {
//				api.createLabel(addr, name, true);
////				}
//
//				if (type == ImportType.FUNCTION) {
//					externalManager.addExtFunction(Library.UNKNOWN, name, addr, SourceType.ANALYSIS);
//				}
//			} catch (Exception e) {
//				e.printStackTrace();
//			}
//		}

//		importPropertiesMap = new HashMap<String, ImportProperty>();
//		HashMap<Function, DecompileResults> decompCache = new HashMap<Function, DecompileResults>();

		// dumps basic blocks of all functions containing data imports
//		List<Function> processed = new ArrayList<Function>();
//		BasicBlockModel blockModel = new BasicBlockModel(program, false);
//		Listing listing = program.getListing();
//
//		try {
//			File file = new File("~/ags/basicblocks.txt");
//			FileWriter writer = new FileWriter(file);
//
//			AddressIterator iter = importProperties.getPropertyIterator();
//			while (iter.hasNext()) {
//				Address address = iter.next();
//
//				ImportProperty prop = (ImportProperty) importProperties.get(address);
//				if (prop.getType() == ImportType.DATA) {
//					Function func = api.getFunctionContaining(address);
//					if (!processed.contains(func)) {
//						writer.write(func.getName(true) + ":\n");
//
//						CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(func.getBody(), monitor);
//						while (blockIter.hasNext()) {
//							CodeBlock block = blockIter.next();
//
//							writer.write(String.format("\t[%s]\n", block.getFirstStartAddress().toString(false, true)));
//
//							CodeBlockReferenceIterator blockRefIter = block.getSources(monitor);
//							while (blockRefIter.hasNext()) {
//								CodeBlockReference blockRef = blockRefIter.next();
//								writer.write(
//										String.format("\t\t%s: %s\n", blockRef.getSourceAddress().toString(false, true),
//												blockRef.getFlowType().toString()));
//							}
//
//							InstructionIterator instrIter = listing.getInstructions(block, true);
//							while (instrIter.hasNext()) {
//								Instruction instr = instrIter.next();
//
//								String prefix = " ";
////								String postfix = "";
//								// FIXME(adm244): this is incorrect since doesn't highlight all imports
//								if (instr.contains(address)) {
//									prefix = "*";
////									postfix = String.format(" ; %s", prop.getName());
//								}
//
//								writer.write(String.format("%s\t%s %s\n", prefix, instr.getAddressString(false, true),
//										instr));
//							}
//
//							blockRefIter = block.getDestinations(monitor);
//							while (blockRefIter.hasNext()) {
//								CodeBlockReference blockRef = blockRefIter.next();
//								writer.write(String.format("\t\t%s: %s\n",
//										blockRef.getDestinationAddress().toString(false, true),
//										blockRef.getFlowType().toString()));
//							}
//
//							writer.write("\n");
//						}
//
//						processed.add(func);
//					}
//				}
//			}
//
//			writer.close();
//		} catch (Exception e) {
//			e.printStackTrace();
//		}

//		CodeBlockIterator iter = blockModel.getCodeBlocks(monitor);
//		while (iter.hasNext()) {
//			CodeBlock block = iter.next();
//			block.getName();
//		}

//		DecompInterface decomp = new DecompInterface();
////		DecompileOptions options = new DecompileOptions();
////		decomp.setOptions(options);
//		decomp.openProgram(program);
//
//		monitor.setMaximum(importProperties.getSize());
//		monitor.setProgress(0);
//
//		AddressIterator iter = importProperties.getPropertyIterator();
//		while (iter.hasNext()) {
//			monitor.checkCanceled();
//
//			Address address = iter.next();
//
//			ImportProperty importProperty = (ImportProperty) importProperties.get(address);
//
//			monitor.setProgress(monitor.getProgress() + 1);
//			monitor.setMessage(importProperty.getName());
//
//			if (importProperty.getType() != ImportType.DATA) {
//				continue;
//			}
//
//			String name = importProperty.getName();
//			if (!importPropertiesMap.containsKey(name)) {
//				importPropertiesMap.put(name, importProperty);
//			}
//
//			importProperty = importPropertiesMap.get(name);
//
//			int size = importProperty.getSize();
//
//			try {
//				Address baseAddress = api.toAddr(importProperty.getBaseOffset());
//				AddressRange addressRange = new AddressRangeImpl(baseAddress, ScriptLoader.importMaxSize);
//
//				Function func = api.getFunctionContaining(address);
//				if (func == null) {
//					continue;
//				}
//
//				if (!decompCache.containsKey(func)) {
//					DecompileResults results = decomp.decompileFunction(func, 30, monitor);
//					if (results == null) {
//						continue;
//					}
//
//					decompCache.put(func, results);
//				}
//
//				DecompileResults results = decompCache.get(func);
//				if (!results.decompileCompleted()) {
//					continue;
//				}
//
//				if (importProperty.getName().equals("region")) {
//					Variable[] vars = func.getAllVariables();
//					int d = 0;
//				}
//
//				HighFunction highFunc = results.getHighFunction();
//				GlobalSymbolMap globalSymbols = highFunc.getGlobalSymbolMap();
//
//				Iterator<HighSymbol> symIter = globalSymbols.getSymbols();
//				while (symIter.hasNext()) {
//					HighSymbol sym = symIter.next();
//					SymbolEntry symEntry = sym.getFirstWholeMap();
//					VariableStorage storage = symEntry.getStorage();
//					Address addr = storage.getMinAddress();
//
////					HighVariable var = sym.getHighVariable();
////					if (var == null) {
////						continue;
////					}
////
////					Varnode node = var.getRepresentative();
////					if (node == null) {
////						continue;
////					}
////
////					Address addr = node.getAddress();
//
//					if (addressRange.contains(addr)) {
//						long offset = addr.subtract(addressRange.getMinAddress());
//						if (offset >= size) {
//							size = (int) (offset + 4);
//						}
//					}
//				}
//			} catch (Exception e) {
//				// TODO: handle exception
//				e.printStackTrace();
//			}
//
//			importProperty.setSize(size);
//		}
////
		// STEP 2. Figure out data import sizes
//		analyzeImportDataSizes(program, set, monitor, log);

//		long i = 1;
//		for (Entry<String, ImportProperty> entry : importPropertiesMap.entrySet()) {
//			ImportProperty importProperty = entry.getValue();
//
//			Address importAddress = api.toAddr(importProperty.getBaseOffset());
//			String importName = importProperty.getName();
//			ImportType importType = importProperty.getType();
//			int importSize = importProperty.getSize();
//
//			program.getBookmarkManager().setBookmark(importAddress, BookmarkType.ANALYSIS, importType.toString(),
//					"[" + importSize + "] " + importName);
//		}

		// STEP 3. Layout imports and change address references

		// STEP 4. Call it a day :-)

		return true;
	}

//	private void analyzeImportDataSizes(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
//		/*
//		 * Similar to "analyzeImportTypes" track MAR register for additions\subtractions
//		 * and if it's then read\written extend existing data type by how much register
//		 * was shifted.
//		 */
//		Listing listing = program.getListing();
//
//		AddressIterator iter = importProperties.getPropertyIterator(set);
//		while (iter.hasNext()) {
//			Address address = iter.next();
//			ImportProperty importProperty = (ImportProperty) importProperties.get(address);
//
//			if (importProperty.getType() != ImportType.DATA) {
//				continue;
//			}
//
//			String name = importProperty.getName();
//			if (!importPropertiesMap.containsKey(name)) {
//				importPropertiesMap.put(name, importProperty);
//			}
//
//			importProperty = importPropertiesMap.get(name);
//
//			int size = importProperty.getSize();
//
//			Instruction instr = listing.getInstructionContaining(address);
//			try {
//				Register register = getDestinationRegister(instr);
//				if (register == null) {
//					continue;
//				}
//
//				size = doAnalyzeImportDataSize(program, instr.getNext(), register, 0, size);
//			} catch (Exception e) {
//				// TODO: handle exception
//				e.printStackTrace();
//			}
//
//			importProperty.setSize(size);
//
//			// NOTE(adm244): it appears that get() returns a copy
////			importProperties.remove(address);
////			importProperties.add(address, importProperty);
//		}
//	}
//
//	private int doAnalyzeImportDataSize(Program program, Instruction instr, Register traceRegister, int offset,
//			int size) throws MemoryAccessException {
//		if (instr == null) {
//			// FIXME(adm244): this shouldn't happen, limit analysis to a function scope
//			return size;
//		}
//
//		InstructionContext context = instr.getInstructionContext();
//		ParserContext parserContext = context.getParserContext();
//		InstructionPrototype prototype = parserContext.getPrototype();
//
////		Object[] inputs = prototype.getInputObjects(context);
////		Object[] outputs = prototype.getResultObjects(context);
//		PcodeOp[] ops = prototype.getPcode(context, null);
//
//		boolean inputsMatch = containsAsInput(ops, traceRegister);
//		boolean outputsMatch = containsAsOutput(ops, traceRegister);
//
//		// TODO(adm244): analyze array access (trace back register value)
//
//		// traced register is used as an input into this instruction
//		if (inputsMatch) {
//			// NOTE(adm244): assuming it's always first pcode...
//			PcodeOp op = ops[0];
//			Varnode inputNode = op.getInput(1);
//			Register inputRegister = program.getRegister(inputNode);
//
//			switch (op.getOpcode()) {
//			case PcodeOp.INT_ADD:
//				if (inputNode.isRegister()) {
//					offset += traceRegisterBackward(instr.getPrevious(), inputRegister);
//				} else {
//					offset += inputNode.getOffset();
//				}
//				break;
//			case PcodeOp.INT_SUB:
//				if (inputNode.isRegister()) {
//					offset -= traceRegisterBackward(instr.getPrevious(), inputRegister);
//				} else {
//					offset -= inputNode.getOffset();
//				}
//				break;
//
//			case PcodeOp.STORE:
//			case PcodeOp.LOAD:
//				if (offset >= size) {
//					size = offset + 4;
//				}
//				break;
//
//			default:
//				break;
//			}
//		}
//
//		// traced register is used as an output of this instruction
//		else if (!inputsMatch && outputsMatch) {
//			// TODO(adm244): possibly multiple registers to track from here
//			return size;
//		}
//
//		// at this point traced register is either the same or unused
//
//		// skip to the next instruction
//		return doAnalyzeImportDataSize(program, instr.getNext(), traceRegister, offset, size);
//	}
//
//	private int traceRegisterBackward(Instruction instr, Register traceRegister) throws MemoryAccessException {
//		InstructionContext context = instr.getInstructionContext();
//		ParserContext parserContext = context.getParserContext();
//		InstructionPrototype prototype = parserContext.getPrototype();
//
//		Object[] inputs = prototype.getInputObjects(context);
//		Object[] outputs = prototype.getResultObjects(context);
//
//		boolean inputsMatch = contains(inputs, traceRegister);
//		boolean outputsMatch = contains(outputs, traceRegister);
//
//		// traced register is used as an input into this instruction
//		if (inputsMatch && !outputsMatch) {
//			// ignore
//		}
//
//		// traced register is used as an output of this instruction
//		else if (!inputsMatch && outputsMatch) {
//			int type = instr.getOperandType(1);
//
//			PcodeOp op = instr.getPcode(0)[0];
//
//			switch (op.getOpcode()) {
////			case 
//			
//			case PcodeOp.STORE:
//				if (type == OperandType.IMMEDIATE) {
//					return (int) instr.getScalar(1).getValue();
//				} else if (type == OperandType.REGISTER) {
//					Register register = instr.getRegister(1);
//					return traceRegisterBackward(instr.getPrevious(), register);
//				}
//				break;
//			}
//		}
//
//		// at this point traced register is either the same or unused
//
//		// skip to the previous instruction
//		return traceRegisterBackward(instr.getPrevious(), traceRegister);
//	}
//
//	private boolean containsAsInput(PcodeOp[] ops, Register register) {
//		for (int i = 0; i < ops.length; ++i) {
//			for (Varnode node : ops[i].getInputs()) {
//				if (pointsToRegister(node, register)) {
//					return true;
//				}
//			}
//		}
//
//		return false;
//	}
//
//	private boolean containsAsOutput(PcodeOp[] ops, Register register) {
//		for (int i = 0; i < ops.length; ++i) {
//			if (pointsToRegister(ops[i].getOutput(), register)) {
//				return true;
//			}
//		}
//
//		return false;
//	}
//
//	private boolean pointsToRegister(Varnode node, Register register) {
//		if (node != null && node.isRegister()) {
//			if (register != null && node.getAddress().equals(register.getAddress())) {
//				return true;
//			}
//		}
//
//		return false;
//	}

	private void analyzeImportTypes(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		/*
		 * Imported function is never called directly. "farcall" instruction is an
		 * indirect call.
		 */

		Listing listing = program.getListing();

		AddressIterator iter = importProperties.getPropertyIterator(set);
		while (iter.hasNext()) {
			Address address = iter.next();
			ImportProperty importProperty = (ImportProperty) importProperties.get(address);

			ImportType type = importProperty.getType();

			Instruction instr = listing.getInstructionContaining(address);
			try {
				Register register = getDestinationRegister(instr);
				if (register == null) {
					continue;
				}

				type = doAnalyzeImportType(instr.getNext(), register);
			} catch (MemoryAccessException ex) {
				ex.printStackTrace();
			}

			importProperty.setType(type);

			// NOTE(adm244): it appears that get() returns a copy
			importProperties.remove(address);
			importProperties.add(address, importProperty);

//			String importName = importProperty.getName();
//			ImportType importType = importProperty.getType();

//			log.appendMsg(
//					String.format("0x%X: %s, type = %s\n", address.getOffset(), importName, importType.toString()));

//			program.getBookmarkManager().setBookmark(address, BookmarkType.ANALYSIS, importType.toString(), importName);
		}
	}

	private Register getDestinationRegister(Instruction instr) throws MemoryAccessException {
		InstructionContext instrContext = instr.getInstructionContext();
		ParserContext parserContext = instrContext.getParserContext();
		InstructionPrototype prototype = parserContext.getPrototype();

		Object[] resultObjects = prototype.getResultObjects(instrContext);

		// NOTE(adm244): should be only one output
		if (resultObjects.length > 1) {
			return null;
		}

		// NOTE(adm244): only track registers
		if (resultObjects[0].getClass() != Register.class) {
			return null;
		}

		return (Register) resultObjects[0];
	}

	private ImportType doAnalyzeImportType(Instruction instr, Register traceRegister) throws MemoryAccessException {
		// TODO(adm244): cache results so that duplicates are not processed again

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
			// this is the end of a traced registers life, assume import is data
			return ImportType.DATA;
		}

		// at this point traced register is either the same or unused

		// skip to the next instruction
		return doAnalyzeImportType(instr.getNext(), traceRegister);
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

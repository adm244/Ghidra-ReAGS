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

package reags.pcodeInject;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import reags.state.ExternalFunction;
import reags.state.ScriptAnalysisState;

public class ConstantPoolScom3 extends ConstantPool {

//	private static final int POINTER_SIZE = 4;
	private static final int INSTRUCTION_SIZE = 4;

	public static final CategoryPath CPOOL_DATA_PATH = new CategoryPath("/external/data");

	public static final String CPOOL_DATA = "1";
	public static final String CPOOL_FUNCTION = "2";
	public static final String CPOOL_STRING = "3";
	public static final String CPOOL_IMPORT_DATA = "4";
	public static final String CPOOL_IMPORT_FUNCTION = "5";
	public static final String CPOOL_NEW_ARRAY = "6";
	public static final String CPOOL_DATAPOINTER = "7";

//	private Program program;
	private DataTypeManager dtManager;
	private MemoryBlock dataBlock;
	private MemoryBlock codeBlock;
	private ScriptAnalysisState scriptState;

//	private AddressSpace externalSpace;

	public ConstantPoolScom3(Program program) {
//		this.program = program;

		Memory memory = program.getMemory();
		dtManager = program.getDataTypeManager();

		dataBlock = memory.getBlock("data");
		codeBlock = memory.getBlock("code");
		scriptState = ScriptAnalysisState.getState(program);

//		externalSpace = AddressSpace.EXTERNAL_SPACE;
	}

	private DataType getPrimitiveArrayType(int size, boolean isManaged) {
		if (isManaged) {
			return VoidDataType.dataType;
		}

		switch (size) {
		case 1:
			return CharDataType.dataType;
		case 2:
			return ShortDataType.dataType;
		case 4:
			// TODO(adm244): could be bool and float as well...
			return IntegerDataType.dataType;

		default:
			throw new IllegalArgumentException("Invalid primitive size: " + size);
		}
	}

	// ref array does not include the first element passed to the cpool operator.
	// ref[0] is the constant pool index
	// ref[1] is a defined constant which represents the bytecode operation
	@Override
	public Record getRecord(long[] ref) {
		Record record = new Record();

		long index = ref[0];
		String op = Long.toString(ref[1]);

		Address address;

		switch (op) {
		case CPOOL_DATA:
			address = dataBlock.getStart().add(index);
			fillPrimitive(record, address, "pointer");
			break;

		case CPOOL_FUNCTION:
			address = codeBlock.getStart().add(index * INSTRUCTION_SIZE);
			fillPrimitive(record, address, "local_function");
			break;

		case CPOOL_STRING:
			fillStringLiteral(record, index);
			break;

		case CPOOL_IMPORT_DATA: {
			fillImportData(record, scriptState.imports.get(index));
			break;
		}

		case CPOOL_IMPORT_FUNCTION: {
//			String name = scriptState.imports.get(index);
			ExternalFunction function = scriptState.functions.get(index);
			fillPrimitive(record, function.getAddress(), function.getName());

			// TODO(adm244): create a function pointer

//			record.tag = ConstantPool.POINTER_METHOD;
//			record.token = function.getName();
//
//			DataType dt = dtManager.getDataType(new DataTypePath("/external/functions", record.token));
//			if (dt == null) {
//				FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(function.getFunction(), true);
//				funcDef.setCategoryPath(new CategoryPath("/external/functions"));
//
////				ParameterDefinitionImpl[] funcArgs = new ParameterDefinitionImpl[function.getArgumentsCount()];
////				funcDef.setArguments(funcArgs);
//
//				int id = dtManager.startTransaction("function creation");
//				dtManager.addDataType(funcDef, DataTypeConflictHandler.DEFAULT_HANDLER);
//				dtManager.endTransaction(id, true);
//			}

//			FunctionDefinitionDataType func = new FunctionDefinitionDataType(function.getName());
////
//			record.type = new PointerDataType(dt);
			break;
		}

		case CPOOL_NEW_ARRAY: {
			int type = (int) ref[2];

			// FIXME(adm244): doesn't work as it should...
			DataType dataType = getPrimitiveArrayType((int) index, type == 1);

			DataType dt = dtManager.getPointer(dataType);

			record.tag = ConstantPool.POINTER_METHOD;
//			record.tag = ConstantPool.CLASS_REFERENCE;
			record.token = dataType.getDisplayName();
			record.type = dt;
//			record.token = "mytype";
//			record.type = Undefined2DataType.dataType;
//			record.type = new ArrayDataType(dataType, 0, dataType.getLength());
//			record.type = PointerDataType.dataType;

			break;
		}

//		case "5":
//			record.tag = ConstantPool.POINTER_METHOD;
//			record.token = "TestMethod";
//
//			String uniqueifier = Integer.toHexString((int) index);
//			FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(uniqueifier + "_" + record.token);
//
//			DataType returnType = IntegerDataType.dataType;
//			funcDef.setReturnType(returnType);
//
//			ParameterDefinitionImpl[] paramDefs = new ParameterDefinitionImpl[0];
//			funcDef.setArguments(paramDefs);
//
//			record.type = new PointerDataType(funcDef);
//			break;

		case CPOOL_DATAPOINTER:
			address = dataBlock.getStart().add(index);
			fillPrimitive(record, address, "pointer_to_pointer");
			break;

		default:
			break;
		}

		return record;
	}

	private void fillPrimitive(Record record, Address address, String name) {
		record.tag = ConstantPool.PRIMITIVE;
		record.token = name;
		record.value = address.getOffset();
		record.type = PointerDataType.dataType;
	}

	private void fillStringLiteral(Record record, long index) {
		String string = scriptState.strings.get(index);

		record.tag = ConstantPool.STRING_LITERAL;
		// TODO(adm244): since v.3.6.0 string can be in UTF-8 format, implement an
		// option to toggle between Latin1 and UTF-8 encodings
		record.setUTF8Data(string);
		record.type = PointerDataType.dataType;
	}

	private void fillImportData(Record record, String name) {
		DataType dt = dtManager.getDataType(CPOOL_DATA_PATH, name);
		record.tag = ConstantPool.POINTER_FIELD;
		record.token = name;
		record.type = dtManager.getPointer(dt);
	}

}

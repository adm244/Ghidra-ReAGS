package reags.pcodeInject;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import reags.state.ExternalFunction;
import reags.state.ScriptAnalysisState;

public class ConstantPoolScom3 extends ConstantPool {

//	private static final int POINTER_SIZE = 4;
	private static final int INSTRUCTION_SIZE = 4;

	public static final String CPOOL_DATA = "1";
	public static final String CPOOL_FUNCTION = "2";
	public static final String CPOOL_STRING = "3";
	public static final String CPOOL_IMPORT_DATA = "4";
	public static final String CPOOL_IMPORT_FUNCTION = "5";
	public static final String CPOOL_NEW_ARRAY = "6";

	private Program program;
	private DataTypeManager dtManager;
	private MemoryBlock dataBlock;
	private MemoryBlock codeBlock;
	private ScriptAnalysisState scriptState;

//	private AddressSpace externalSpace;

	public ConstantPoolScom3(Program program) {
		this.program = program;

		Memory memory = program.getMemory();
		dtManager = program.getDataTypeManager();

		dataBlock = memory.getBlock("data");
		codeBlock = memory.getBlock("code");
		scriptState = ScriptAnalysisState.getState(program);

//		externalSpace = AddressSpace.EXTERNAL_SPACE;
	}

//	private String getType(String name) {
//		return null;
//	}

	private DataType getPrimitiveArrayType(int size) {
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
//			address = externalBlock.getStart().add(index * POINTER_SIZE);
			String name = scriptState.imports.get(index);
//			address = externalSpace.getAddress(index * POINTER_SIZE);
//			fillPrimitive(record, address, name);

			// TODO(adm244): get type name from 'name' if any, otherwise it's a simple type
//			String type = getType(name);

			// TODO(adm244): get DataType or create it then assign pointer to it
			// this way we don't need to hold the data in memory and can change its size

//			AddressSpace varSpace = new GenericAddressSpace(name, 32, AddressSpace.TYPE_VARIABLE,
//					program.getAddressFactory().getNumAddressSpaces() + 1);
//			Address varAddress = varSpace.getAddress(0);

			// FIXME(adm244): move this into analyzer/loader
			DataType dt = dtManager.getDataType(new DataTypePath("/external/data", name));
//			if (dt == null) {
////				dt = new TypedefDataType(name, DataType.DEFAULT);
//				dt = new StructureDataType(new CategoryPath("/external/data"), name, 0);
//
//				int id = dtManager.startTransaction("CREATION:" + name);
//				dtManager.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
//				dtManager.endTransaction(id, true);
//			}

			record.tag = ConstantPool.POINTER_FIELD;
//			record.token = "DATA:" + name;
			record.token = name;
//			record.type = PointerDataType.dataType;
			record.type = dtManager.getPointer(dt);
			break;
		}

		case CPOOL_IMPORT_FUNCTION: {
//			String name = scriptState.imports.get(index);
			ExternalFunction function = scriptState.functions.get(index);
			fillPrimitive(record, function.getAddress(), function.getName());

			// TODO(adm244): create a function pointer

//			record.tag = ConstantPool.POINTER_METHOD;
//			record.token = "FUNCTION:" + function.getName();
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
//
//			record.type = new PointerDataType(dt);
			break;
		}

		case CPOOL_NEW_ARRAY: {
			int type = (int) ref[2];

			// FIXME(adm244): doesn't work as it should...
			DataType dataType = getPrimitiveArrayType((int) index);

			DataType dt = dtManager.getPointer(dataType);

			record.tag = ConstantPool.POINTER_FIELD;
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

}

package reags.pcodeInject;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import reags.state.ScriptAnalysisState;

public class ConstantPoolScom3 extends ConstantPool {

	private static final int INSTRUCTION_SIZE = 4;

	public static final String CPOOL_DATA = "1";
	public static final String CPOOL_FUNCTION = "2";
	public static final String CPOOL_STRING = "3";

	private Program program;
	private MemoryBlock dataBlock;
	private MemoryBlock codeBlock;
	private ScriptAnalysisState scriptState;

	public ConstantPoolScom3(Program program) {
		this.program = program;

		Memory memory = program.getMemory();

		dataBlock = memory.getBlock("data");
		codeBlock = memory.getBlock("code");
		scriptState = ScriptAnalysisState.getState(program);
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

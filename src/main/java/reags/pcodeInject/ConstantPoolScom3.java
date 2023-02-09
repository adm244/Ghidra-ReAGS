package reags.pcodeInject;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Program;

public class ConstantPoolScom3 extends ConstantPool {

	public ConstantPoolScom3(Program program) {
		// TODO Auto-generated constructor stub
	}
	
	// ref array does not include the first element passed to the cpool operator.
	// ref[0] is the constant pool index
	// ref[1] is a defined constant which represents the bytecode operation
	@Override
	public Record getRecord(long[] ref) {
		Record record = new Record();

		long index = ref[0];
		String op = Long.toString(ref[1]);

		switch (op) {
		case "5":
			record.tag = ConstantPool.POINTER_METHOD;
			record.token = "TestMethod";

			String uniqueifier = Integer.toHexString((int) index);
			FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(uniqueifier + "_" + record.token);

			DataType returnType = IntegerDataType.dataType;
			funcDef.setReturnType(returnType);

			ParameterDefinitionImpl[] paramDefs = new ParameterDefinitionImpl[0];
			funcDef.setArguments(paramDefs);

			record.type = new PointerDataType(funcDef);
			break;

		default:
			break;
		}

		return record;
	}

}

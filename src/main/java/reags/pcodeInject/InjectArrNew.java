package reags.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class InjectArrNew extends InjectPayloadFarStack {

	private static final int PTR_TYPE_PRIMITIVE = 0;
	private static final int PTR_TYPE_MANAGED = 1;

	public InjectArrNew(SleighLanguage language, long uniqueBase) {
		super("arrnew", language, uniqueBase);
	}

//	@Override
//	public PcodeOp[] getPcode(Program program, InjectContext context) {
//		Varnode count = context.inputlist.get(0);
//		long size = context.inputlist.get(1).getOffset();
//		int ptrType = (int) context.inputlist.get(2).getOffset();
//		
//		Varnode output = context.output.get(0);
//
//		MyPcodeOpEmitter pcode = new MyPcodeOpEmitter(language, context.baseAddr, uniqueBase);
//
//		switch (ptrType) {
//		case PTR_TYPE_PRIMITIVE:
//			break;
//
//		case PTR_TYPE_MANAGED:
//			pcode.emitAssignCPoolRef(PARAMETER, ConstantPoolScom3.CPOOL_NEW_ARRAY_MANAGED, Long.toString(size));
//			pcode.emitNew(output, PARAMETER, count);
//			break;
//
//		default:
//			return null;
//		}
//
//		return pcode.getPcodeOps();
//	}

}

package reags.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import reags.state.FunctionState;

public class InjectFarPush extends InjectPayloadFarStack {

	public InjectFarPush(SleighLanguage language, long uniqueBase) {
		super("farpush", language, uniqueBase);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		// NOTE(adm244): ignore symbolic propagator call
		if (!context.inputlist.get(0).isRegister()) {
			return new PcodeOp[0];
		}

		MyPcodeOpEmitter pCode = new MyPcodeOpEmitter(language, context.baseAddr, uniqueBase);

		pCode.emitPushCat1Value("ax");
		
//		Address address = getFunctionAddress(program, context);
//		FunctionState state = getFunctionState(program, address);

//		int argumentsCount = state.getArgumentsCount();

//		int totalSize = 1000;
//		for (int i = 0; i < argumentsCount; ++i) {
//			pCode.emitPopCat1Value(PARAMETER + Integer.toString(i));
//			pCode.emitWriteToMemory(PARAM_SPACE, 4, Integer.toString(totalSize) + ":4",
//					PARAMETER + Integer.toString(i));
//			totalSize -= 4;
//		}
//
//		pCode.emitIndirectCall("ax");

		return pCode.getPcodeOps();

//		Address address = getFunctionAddress(program, context);
//		FunctionState state = getFunctionState(program, address);
//
//		Varnode node = context.inputlist.get(0);
//
//		Stack<Varnode> farStack = state.getFarStack();
//		farStack.push(node);
//
////		return new PcodeOp[0];
//		
//		Register reg = program.getRegister("ax");
//		Varnode ax = new Varnode(reg.getAddress(), 4);
//		
//		PcodeOp nop = new PcodeOp(context.baseAddr, 0, PcodeOp.COPY);
//		nop.setInput(ax, 0);
//		nop.setOutput(ax);
//		
//		return new PcodeOp[] { nop };
	}

}

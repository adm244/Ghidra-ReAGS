package reags.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import reags.state.FunctionState;

public class InjectSetFuncArgs extends InjectPayloadFarStack {

	public InjectSetFuncArgs(SleighLanguage language, long uniqueBase) {
		super("setfuncargs", language, uniqueBase);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		Address address = getFunctionAddress(program, context);
		FunctionState state = getFunctionState(program, address);

		int value = (int) context.inputlist.get(0).getOffset();
		state.setArgumentsCount(value);

//		return new PcodeOp[0];
		
		Register reg = program.getRegister("ax");
		Varnode ax = new Varnode(reg.getAddress(), 4);
		
		PcodeOp nop = new PcodeOp(context.baseAddr, 0, PcodeOp.COPY);
		nop.setInput(ax, 0);
		nop.setOutput(ax);
		
		return new PcodeOp[] { nop };
	}

}

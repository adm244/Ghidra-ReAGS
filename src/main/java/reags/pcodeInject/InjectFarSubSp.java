package reags.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.datastruct.Stack;
import reags.state.FunctionState;

public class InjectFarSubSp extends InjectPayloadFarStack {

	public InjectFarSubSp(SleighLanguage language, long uniqueBase) {
		super("farsubsp", language, uniqueBase);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		// NOTE(adm244): ignore symbolic propagator call
		if (!context.inputlist.get(0).isRegister()) {
			return new PcodeOp[0];
		}

		Address address = getFunctionAddress(program, context);
		FunctionState state = getFunctionState(program, address);

		Stack<Varnode> stack = state.getFarStack();

		int count = (int) context.inputlist.get(1).getOffset();

		for (int i = 0; i < count; ++i) {
			stack.pop();
		}

//		return new PcodeOp[0];

		Register reg = program.getRegister("ax");
		Varnode ax = new Varnode(reg.getAddress(), 4);

		PcodeOp nop = new PcodeOp(context.baseAddr, 0, PcodeOp.COPY);
		nop.setInput(ax, 0);
		nop.setOutput(ax);

		return new PcodeOp[] { nop };
	}

}

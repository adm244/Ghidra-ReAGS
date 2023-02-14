package reags.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

public class InjectMemZero extends InjectPayloadFarStack {

	private static String ZERO = "0";

	private String defaultSpaceName;

	public InjectMemZero(SleighLanguage language, long uniqueBase) {
		super("memzero", language, uniqueBase);

		AddressSpace defaultSpace = language.getDefaultSpace();
		defaultSpaceName = defaultSpace.getName();
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		MyPcodeOpEmitter pcode = new MyPcodeOpEmitter(language, context.baseAddr, uniqueBase);

		int size = (int) context.inputlist.get(0).getOffset();

		pcode.emitAssignConstant(ZERO, 0, size);
		pcode.emitWriteToMemory(defaultSpaceName, size, "mar", ZERO);

		return pcode.getPcodeOps();
	}

}

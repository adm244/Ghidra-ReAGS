package reags.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

public class InjectMemCpy extends InjectPayloadFarStack {

	private String defaultSpaceName;

	public InjectMemCpy(SleighLanguage language, long uniqueBase) {
		super("memcpy", language, uniqueBase);

		AddressSpace defaultSpace = language.getDefaultSpace();
		defaultSpaceName = defaultSpace.getName();
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		MyPcodeOpEmitter pcode = new MyPcodeOpEmitter(language, context.baseAddr, uniqueBase);

		int value = (int) context.inputlist.get(0).getOffset();
		int size = (int) context.inputlist.get(1).getOffset();

		switch (size) {
		case 1:
		case 2:
		case 4:
			break;

		default:
			// memcpy size is not supported
			return null;
		}

		String paramName = Integer.toString(value);
		
		pcode.emitAssignConstant(paramName, value, size);
		pcode.emitWriteToMemory(defaultSpaceName, size, "mar", paramName);

		return pcode.getPcodeOps();
	}

}

package reags.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import reags.analyzers.FixupType;
import reags.state.ScriptAnalysisState;

public class InjectMovLit extends InjectPayloadFarStack {

	public InjectMovLit(SleighLanguage language, long uniqueBase) {
		super("movlit", language, uniqueBase);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		Varnode output = context.output.get(0);
		Varnode value = context.inputlist.get(0);

		ScriptAnalysisState state = ScriptAnalysisState.getState(program);
		FixupType fixupType = state.fixups.getOrDefault(context.baseAddr, FixupType.UNDEFINED);

		MyPcodeOpEmitter pcode = new MyPcodeOpEmitter(language, context.baseAddr, uniqueBase);

		switch (fixupType) {
		case DATA:
			pcode.emitAssignCPoolRef(output, value, ConstantPoolScom3.CPOOL_DATA);
			break;

		case FUNCTION:
			pcode.emitAssignCPoolRef(output, value, ConstantPoolScom3.CPOOL_FUNCTION);
			break;

		case STRING:
			pcode.emitAssignCPoolRef(output, value, ConstantPoolScom3.CPOOL_STRING);
			break;

		case IMPORT_DATA:
			pcode.emitAssignCPoolRef(output, value, ConstantPoolScom3.CPOOL_IMPORT_DATA);
			break;

		case IMPORT_FUNCTION:
			pcode.emitAssignCPoolRef(output, value, ConstantPoolScom3.CPOOL_IMPORT_FUNCTION);
			break;
			
		case DATAPOINTER:
			pcode.emitAssignCPoolRef(output, value, ConstantPoolScom3.CPOOL_DATAPOINTER);
			break;

		default:
			pcode.emitAssignImmediate(output, value);
			break;
		}

		return pcode.getPcodeOps();
	}

}

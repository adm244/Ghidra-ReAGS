package reags.pcodeInject;

import java.util.List;

import ghidra.app.plugin.core.analysis.AnalysisStateInfo;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import reags.state.FarStackAnalysisState;
import reags.state.FunctionState;
import reags.state.ScriptAnalysisState;

public class InjectPayloadFarStack extends InjectPayloadCallother {

	protected String PARAMETER = "PARAM";
	protected String PARAM_SPACE = "paramStack";
	
	protected SleighLanguage language;
	protected long uniqueBase;
	
	public InjectPayloadFarStack(String sourceName, SleighLanguage language, long uniqueBase) {
		super(sourceName);
		this.language = language;
		this.uniqueBase = uniqueBase;
	}

	public FunctionState getFunctionState(Program program, Address address) {
		FarStackAnalysisState analysisState = getFarStackAnalysisState(program);

		FunctionState functionState = analysisState.getFunctionState(address);
		if (functionState == null) {
			functionState = new FunctionState();
			analysisState.putFunctionState(address, functionState);
		}

		return functionState;
	}

	private synchronized FarStackAnalysisState getFarStackAnalysisState(Program program) {
		FarStackAnalysisState analysisState = AnalysisStateInfo.getAnalysisState(program, FarStackAnalysisState.class);
		if (analysisState == null) {
			analysisState = new FarStackAnalysisState(program);
			AnalysisStateInfo.putAnalysisState(program, analysisState);
		}

		return analysisState;
	}

	public Address getFunctionAddress(Program program, InjectContext context) {
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionContaining(context.baseAddr);
		return function.getEntryPoint();
	}

	public PcodeOp[] getPcodeOps(List<PcodeOp> opList) {
		PcodeOp[] result = new PcodeOp[opList.size()];
		opList.toArray(result);
		return result;
	}

}

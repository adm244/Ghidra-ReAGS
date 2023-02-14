package reags.state;

import java.util.HashMap;

import ghidra.app.plugin.core.analysis.AnalysisState;
import ghidra.app.plugin.core.analysis.AnalysisStateInfo;
import ghidra.program.model.listing.Program;

public class FarCallAnalysisState implements AnalysisState {

	public HashMap<Long, ExternalFunction> functions;

	private FarCallAnalysisState(Program program) {
		functions = new HashMap<Long, ExternalFunction>();
	}

	public static FarCallAnalysisState getState(Program program) {
		FarCallAnalysisState analysisState = AnalysisStateInfo.getAnalysisState(program, FarCallAnalysisState.class);
		if (analysisState == null) {
			analysisState = new FarCallAnalysisState(program);
			AnalysisStateInfo.putAnalysisState(program, analysisState);
		}

		return analysisState;
	}

}

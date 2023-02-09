package reags.state;

import java.util.HashMap;

import ghidra.app.plugin.core.analysis.AnalysisState;
import ghidra.app.plugin.core.analysis.AnalysisStateInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class ScriptAnalysisState implements AnalysisState {

	private Program program;

	public HashMap<Address, Integer> fixups;
	public HashMap<Long, String> strings;

	public ScriptAnalysisState(Program program) {
		this.program = program;

		fixups = new HashMap<Address, Integer>();
		strings = new HashMap<Long, String>();
	}

	public static ScriptAnalysisState getState(Program program) {
		ScriptAnalysisState analysisState = AnalysisStateInfo.getAnalysisState(program, ScriptAnalysisState.class);
		if (analysisState == null) {
			analysisState = new ScriptAnalysisState(program);
			AnalysisStateInfo.putAnalysisState(program, analysisState);
		}

		return analysisState;
	}

}

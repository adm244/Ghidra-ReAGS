package reags.state;

import java.util.HashMap;

import ghidra.app.plugin.core.analysis.AnalysisState;
import ghidra.app.plugin.core.analysis.AnalysisStateInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import reags.analyzers.FixupType;

public class ScriptAnalysisState implements AnalysisState {

	private Program program;

	public HashMap<Address, FixupType> fixups;
	public HashMap<Long, String> strings;
	public HashMap<Long, String> imports;
	public HashMap<Long, Address> functions;

	public ScriptAnalysisState(Program program) {
		this.program = program;

		fixups = new HashMap<Address, FixupType>();
		strings = new HashMap<Long, String>();
		imports = new HashMap<Long, String>();
		functions = new HashMap<Long, Address>();
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

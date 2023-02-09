package reags.state;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AnalysisState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class FarStackAnalysisState implements AnalysisState {

	private Map<Address, FunctionState> functionStates;

	public FarStackAnalysisState(Program program) {
		functionStates = new HashMap<Address, FunctionState>();
	}

	public synchronized FunctionState getFunctionState(Address address) {
		return functionStates.get(address);
	}

	public synchronized void putFunctionState(Address address, FunctionState state) {
		functionStates.put(address, state);
	}

}

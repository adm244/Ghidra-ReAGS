/*
 * This is free and unencumbered software released into the public domain.
 * 
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 * 
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
*/

package reags.state;

import java.util.HashMap;

import ghidra.app.plugin.core.analysis.AnalysisState;
import ghidra.app.plugin.core.analysis.AnalysisStateInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import reags.analyzers.FixupType;

public class ScriptAnalysisState implements AnalysisState {

	public static final String SCRIPT_ANALYSIS_STATE = "SCRIPT_ANALYSIS_STATE";

//	private Program program;

	public HashMap<Address, FixupType> fixups;
	public HashMap<Long, String> strings;
	public HashMap<Long, String> imports;
	public HashMap<Long, ExternalFunction> functions;
	public HashMap<Long, String> data;
//	public HashMap<Long, Address> pointers;

	private ScriptAnalysisState(Program program) {
//		this.program = program;

		fixups = new HashMap<Address, FixupType>();
		strings = new HashMap<Long, String>();
		imports = new HashMap<Long, String>();
		functions = new HashMap<Long, ExternalFunction>();
		data = new HashMap<Long, String>();
//		pointers = new HashMap<Long, Address>();
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

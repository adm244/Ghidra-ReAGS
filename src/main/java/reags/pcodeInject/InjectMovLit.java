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

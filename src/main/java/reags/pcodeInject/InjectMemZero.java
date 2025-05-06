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

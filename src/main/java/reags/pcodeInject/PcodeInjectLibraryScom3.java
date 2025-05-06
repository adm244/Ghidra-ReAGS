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

/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reags.pcodeInject;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.Program;

public class PcodeInjectLibraryScom3 extends PcodeInjectLibrary {

	private static final long UNIQUE_ENTRY_SIZE = 0x100;

	public static final String MEMCPY = "memcpyCallOther";
	public static final String MOVLIT = "movlitCallOther";
	public static final String FARCALL = "farcallCallOther";
	public static final String MEMZERO = "memzeroCallOther";
//	public static final String ARRNEW = "arrnewCallOther";

	public Map<String, InjectPayload> implementedOps;

	public PcodeInjectLibraryScom3(SleighLanguage language) {
		super(language);

		implementedOps = new HashMap<String, InjectPayload>();
		implementedOps.put(MEMCPY, new InjectMemCpy(language, getNextUniqueBase()));
		implementedOps.put(MOVLIT, new InjectMovLit(language, getNextUniqueBase()));
		implementedOps.put(FARCALL, new InjectFarCall(language, getNextUniqueBase()));
		implementedOps.put(MEMZERO, new InjectMemZero(language, getNextUniqueBase()));
//		implementedOps.put(ARRNEW, new InjectArrNew(language, getNextUniqueBase()));
	}

	public PcodeInjectLibraryScom3(PcodeInjectLibraryScom3 op2) {
		super(op2);
	}

	// NOTE(adm244): this override is essential, because decompiler callback is
	// using a cloned version, unlike analyzers which access original object.
	@Override
	public PcodeInjectLibrary clone() {
		return new PcodeInjectLibraryScom3(this);
	}

	@Override
	public InjectPayload allocateInject(String sourceName, String name, int type) {
		if (type == InjectPayload.CALLMECHANISM_TYPE) {
//			return new InjectPayloadUponEntry(name, sourceName, language, getNextUniqueBase());
		} else if (type == InjectPayload.CALLOTHERFIXUP_TYPE) {
			InjectPayload payload = implementedOps.get(name);
			if (payload != null) {
				return payload;
			}
		}

		return super.allocateInject(sourceName, name, type);
	}

	@Override
	public ConstantPool getConstantPool(Program program) throws IOException {
		return new ConstantPoolScom3(program);
	}

	private long getNextUniqueBase() {
		long result = 0x400000;
		uniqueBase += UNIQUE_ENTRY_SIZE;
		return result;
	}

}

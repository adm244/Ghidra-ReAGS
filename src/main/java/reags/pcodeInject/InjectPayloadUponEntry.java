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

import static ghidra.program.model.pcode.AttributeId.ATTRIB_DYNAMIC;
import static ghidra.program.model.pcode.AttributeId.ATTRIB_INJECT;
import static ghidra.program.model.pcode.ElementId.ELEM_PCODE;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;

public class InjectPayloadUponEntry implements InjectPayload {

	private String name;
	private String sourceName;
	private InjectParameter[] noParams;
	private AddressSpace constantSpace;
	private Varnode zero;
	private Varnode farsp;

	public InjectPayloadUponEntry(String nm, String srcName, SleighLanguage language,
			long uniqBase) {
		name = nm;
		sourceName = srcName;
		noParams = new InjectParameter[0];
		constantSpace = language.getAddressFactory().getConstantSpace();
		zero = new Varnode(constantSpace.getAddress(0), 4);
		Address farspAddress = language.getRegister("_farsp").getAddress();
		farsp = new Varnode(farspAddress, 4);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getType() {
		return CALLMECHANISM_TYPE;
	}

	@Override
	public String getSource() {
		return sourceName;
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public InjectParameter[] getInput() {
		return noParams;
	}

	@Override
	public InjectParameter[] getOutput() {
		return noParams;
	}

	@Override
	public boolean isErrorPlaceholder() {
		return false;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		// Provide a minimal tag so decompiler can call-back
		encoder.openElement(ELEM_PCODE);
		encoder.writeString(ATTRIB_INJECT, "uponentry");
		encoder.writeBool(ATTRIB_DYNAMIC, true);
		encoder.closeElement(ELEM_PCODE);
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) {
		//not used
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOp[] resOps = new PcodeOp[1];
		int seqNum = 0;

		//initialize _farsp to contain 1000
		PcodeOp copy = new PcodeOp(con.baseAddr, seqNum, PcodeOp.COPY);
		copy.setInput(zero, 0);
		copy.setOutput(farsp);
		resOps[seqNum++] = copy;
		
		return resOps;
	}

	@Override
	public boolean isFallThru() {
		return true;
	}

	@Override
	public boolean isIncidentalCopy() {
		return false;
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException {
		XmlElement el = parser.start();
		String injectString = el.getAttribute("inject");
		if (injectString == null || !injectString.equals("uponentry")) {
			throw new XmlParseException("Expecting inject=\"uponentry\" attribute");
		}
		boolean isDynamic = SpecXmlUtils.decodeBoolean(el.getAttribute("dynamic"));
		if (!isDynamic) {
			throw new XmlParseException("Expecting dynamic attribute");
		}
		parser.end(el);
	}

	@Override
	public boolean isEquivalent(InjectPayload obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		InjectPayloadUponEntry op2 = (InjectPayloadUponEntry) obj;
		if (!name.equals(op2.name)) {
			return false;
		}
		if (!sourceName.equals(op2.sourceName)) {
			return false;
		}
		return true;
	}
}

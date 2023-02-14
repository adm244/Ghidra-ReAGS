package reags.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayloadCallother;

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

}

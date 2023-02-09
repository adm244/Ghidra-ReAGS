package reags.state;

import ghidra.program.model.pcode.Varnode;
import ghidra.util.datastruct.Stack;

public class FunctionState {

	public static final int INVALID_ARGS = -1;

	private int argumentsCount;
	private Stack<Varnode> farStack;

	public FunctionState() {
		argumentsCount = INVALID_ARGS;
		farStack = new Stack<Varnode>();
	}

	public int getArgumentsCount() {
		return argumentsCount;
	}

	public void setArgumentsCount(int value) {
		argumentsCount = value;
	}

	public Stack<Varnode> getFarStack() {
		return farStack;
	}

}

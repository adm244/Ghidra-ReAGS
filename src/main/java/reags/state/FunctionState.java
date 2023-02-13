package reags.state;

public class FunctionState {

	public static final int INVALID_ARGS = -1;

	private int argumentsCount;
//	private boolean nextCallRequiresObject;
//	private Stack<Varnode> farStack;

	public FunctionState() {
		argumentsCount = INVALID_ARGS;
//		nextCallRequiresObject = false;
//		farStack = new Stack<Varnode>();
	}

	public int getArgumentsCount() {
		return argumentsCount;
	}

	public void setArgumentsCount(int value) {
		argumentsCount = value;
	}

//	public boolean isNextCallRequiresObject() {
//		return nextCallRequiresObject;
//	}

//	public void setNextCallRequiresObject(boolean value) {
//		nextCallRequiresObject = value;
//	}

//	public Stack<Varnode> getFarStack() {
//		return farStack;
//	}

}

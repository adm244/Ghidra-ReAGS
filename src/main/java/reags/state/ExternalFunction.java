package reags.state;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class ExternalFunction {

	private Address address;
	private String name;
	private boolean hasThis;
	private int argumentsCount;

	private Function function;

	public ExternalFunction(Address address, String name, boolean hasThis, int argumentsCount) {
		this.address = address;
		this.name = name;
		this.hasThis = hasThis;
		this.argumentsCount = argumentsCount;

		function = null;
	}

	public Address getAddress() {
		return address;
	}

	public String getName() {
		return name;
	}

	public boolean hasThis() {
		return hasThis;
	}

	public int getArgumentsCount() {
		return argumentsCount;
	}

	public Function getFunction() {
		return function;
	}

	public void setFunction(Function function) {
		this.function = function;
	}

}

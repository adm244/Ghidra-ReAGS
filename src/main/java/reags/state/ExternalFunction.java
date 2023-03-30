package reags.state;

import ghidra.program.model.address.Address;

public class ExternalFunction {

	private Address address;
	private String name;
	private boolean hasThis;
	private int argumentsCount;

	public ExternalFunction(Address address, String name, boolean hasThis, int argumentsCount) {
		this.address = address;
		this.name = name;
		this.hasThis = hasThis;
		this.argumentsCount = argumentsCount;
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

}

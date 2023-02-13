package reags.state;

import ghidra.program.model.address.Address;

public class ExternalFunction {

	private Address address;
	private String name;
	private boolean hasThis;

	public ExternalFunction(Address address, String name, boolean hasThis) {
		this.address = address;
		this.name = name;
		this.hasThis = hasThis;
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

}

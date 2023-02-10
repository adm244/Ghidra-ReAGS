package reags.analyzers;

/**
 * Fixup types used by SCOM3 analyzers
 */
public enum FixupType {

	/**
	 * Undefined fixup type
	 */
	UNDEFINED,
	
	/**
	 * Immediate value
	 */
	LITERAL,

	/**
	 * Pointer to data in global data section
	 */
	DATA,

	/**
	 * Pointer to a local function in code section
	 */
	FUNCTION,

	/**
	 * Pointer to a null-terminated string in strings section
	 */
	STRING,

	/**
	 * Pointer to an external data
	 */
	IMPORT_DATA,

	/**
	 * Pointer to an external function
	 */
	IMPORT_FUNCTION,

	/**
	 * Pointer to a pointer stored in global data section
	 */
	DATAPOINTER,

	/**
	 * TODO: figure out what this value is actually about
	 */
	STACK

}

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

package reags.scom3;

public class ScriptFixup {

	/**
	 * Immediate value
	 */
	public static final int LITERAL = 0;

	/**
	 * Offset into .data memory block pointing to data
	 */
	public static final int DATA = 1;

	/**
	 * Index into .code memory block as integers array
	 */
	public static final int FUNCTION = 2;

	/**
	 * Offset into .strings memory block pointing a to null-terminated string
	 */
	public static final int STRING = 3;

	/**
	 * Index into .imports memory block as strings array
	 */
	public static final int IMPORT = 4;

	/**
	 * Offset into .data memory block pointing to a pointer to data
	 */
	public static final int DATAPOINTER = 5;

	/**
	 * TODO: figure out what this value is actually about
	 */
	public static final int STACK = 6;

	private byte type;
	private int offset;

	public ScriptFixup() {
		// TODO Auto-generated constructor stub
	}

	public byte getType() {
		return type;
	}

	public void setType(byte type) {
		this.type = type;
	}

	public int getOffset() {
		return offset;
	}

	public void setOffset(int offset) {
		this.offset = offset;
	}

}

package reags.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import reags.state.FunctionState;

public class InjectFarCall extends InjectPayloadFarStack {

	/*
	 * Injection payload for "farcallCallOther" custom p-code.
	 * 
	 * First input is a register that holds a function address.
	 */

	public InjectFarCall(SleighLanguage language, long uniqueBase) {
		super("farcall", language, uniqueBase);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		// NOTE(adm244): ignore symbolic propagator call
		if (!context.inputlist.get(0).isRegister()) {
			// FIXME(adm244): remove this (since this should be in a loader code)
			FlatProgramAPI api = new FlatProgramAPI(program);

			long offset = context.inputlist.get(0).getOffset();

			try {
				Address externalAddress = api.toAddr(offset);

				if (api.getFunctionAt(externalAddress) == null) {
					Function externalFunction = api.createFunction(externalAddress, null);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation = externalManager.addExtFunction(Library.UNKNOWN,
							externalFunction.getName(), null, SourceType.IMPORTED);

					externalFunction.setThunkedFunction(externalLocation.getFunction());
				}
			} catch (Exception e) {
				// TODO: handle exception
			}

			return new PcodeOp[0];
		}

		MyPcodeOpEmitter pCode = new MyPcodeOpEmitter(language, context.baseAddr, uniqueBase);

//		Address address = getFunctionAddress(program, context);
//		FunctionState state = getFunctionState(program, address);

//		int argumentsCount = state.getArgumentsCount();
		int argumentsCount = 1;
		// TODO(adm244): handle the case when argumentsCount is not set

		int totalSize = 1000;
		for (int i = 0; i < argumentsCount; ++i) {
			pCode.emitPopCat1Value(PARAMETER + Integer.toString(i));
			pCode.emitWriteToMemory(PARAM_SPACE, 4, Integer.toString(totalSize) + ":4",
					PARAMETER + Integer.toString(i));
			totalSize -= 4;
		}

		Varnode registerNode = context.inputlist.get(0);
		Register register = program.getRegister(registerNode);
		pCode.emitIndirectCall(register.getName());

		return pCode.getPcodeOps();

//		List<PcodeOp> ops = new ArrayList<PcodeOp>();
//
//		Address address = getFunctionAddress(program, context);
//		FunctionState state = getFunctionState(program, address);
//
////		synchronized (state) {
//		int argumentsCount = state.getArgumentsCount();
////		Stack<Varnode> stack = state.getFarStack();
//
//		// FIXME(adm244): the problem here is that inputlist contains registers and not
//		// values they're holding. Maybe we should utilize "cpool" or read\write into
//		// special memory directly?
//
////		int argumentsCount = (int) context.inputlist.get(0).getOffset();
////		long calleeOffset = context.inputlist.get(1).getOffset();
//
//		// if there were no "setfuncargs" instruction before "farcall" use all arguments
//		// pushed onto the stack (according to agsvm behavior)
//		if (argumentsCount < 0) {
////			argumentsCount = stack.size();
//			return null;
//		}
//
//		// move arguments into farstack address space
//		AddressSpace space = program.getAddressFactory().getAddressSpace("paramStack");
//		AddressSpace farStackSpace = program.getAddressFactory().getAddressSpace("farStack");
//		AddressSpace constSpace = program.getAddressFactory().getConstantSpace();
//		AddressSpace uniqueSpace = program.getAddressFactory().getUniqueSpace();
////		AddressSpace registerSpace = program.getAddressFactory().getRegisterSpace();
//
//		Register regFarStack = program.getRegister("_farsp");
//		Varnode farsp = new Varnode(regFarStack.getAddress(), regFarStack.getBitLength() / 8);
//
//		int base = 0;
//
////		Varnode[] args = new Varnode[argumentsCount + 1];
////		args[0] = context.inputlist.get(0);
//
////		{
////			Varnode out = new Varnode(uniqueSpace.getAddress(1024410), 4);
////			Varnode[] in = new Varnode[2];
////			in[0] = new Varnode(constSpace.getAddress(registerSpace.getSpaceID()), 4);
////			in[1] = context.inputlist.get(0);
////		
////			ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.LOAD, in, out));
////			
////			args[0] = out;
////		}
//
//		for (int i = 0; i < argumentsCount; ++i) {
////			Varnode out = new Varnode(space.getAddress(1000 - (i * 4)), 4);
//			Varnode out = new Varnode(uniqueSpace.getAddress(context.baseAddr.getOffset() + (i * 4)), 4);
//			Varnode param = new Varnode(uniqueSpace.getAddress(context.baseAddr.getOffset() + 2000 + (i * 4)), 4);
//
//			// out = farsp - (4 * (i + 1))
//			// param[i] = out
//
////			{
////				Varnode[] in = new Varnode[2];
////				in[0] = new Varnode(constSpace.getAddress(i + 1), 4);
////				in[1] = new Varnode(constSpace.getAddress(4), 4);
////
////				ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.INT_MULT, in, out));
////			}
//			{
//				Varnode[] in14 = new Varnode[2];
//				in14[0] = farsp;
////				in14[1] = new Varnode(constSpace.getAddress((i + 1) * 4), 4);
//				in14[1] = new Varnode(constSpace.getAddress(4), 4);
//
//				ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.INT_SUB, in14, farsp));
//			}
//			{
//				Varnode[] in = new Varnode[2];
//				in[0] = new Varnode(constSpace.getAddress(farStackSpace.getSpaceID()), 4);
//				in[1] = farsp;
//
//				ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.LOAD, in, param));
//			}
//
////			args[i + 1] = out;
//
//			Varnode[] in = new Varnode[3];
//
//			in[0] = new Varnode(constSpace.getAddress(space.getSpaceID()), 4);
//			in[1] = new Varnode(constSpace.getAddress(1000 - (i * 4)), 4);
//
//			// FIXME(adm244): sadly, we cannot use stack here, because it holds a register
//			// and not its value, so every argument becomes the same here... :(
////			in[2] = stack.get(stack.size() - 1 - i);
//
//			// FIXME(adm244): temporary function params
////			in[2] = new Varnode(constSpace.getAddress(i + 1), 4);
//			in[2] = param;
//
//			ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.STORE, in));
//		}
//
////		// ### CALLIND dx
//		Varnode[] in = new Varnode[1];
////
//////			AddressSpace registerSpace = program.getAddressFactory().getRegisterSpace();
//////			Address addr = registerSpace.getAddress(context.inputlist.get(1).getOffset());
//////			
//////			Register register = program.getRegister("ax");
//////			Address addr = register.getAddress();
////
////		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(calleeOffset);
////		in[0] = new Varnode(addr, addr.getPointerSize());
//		in[0] = context.inputlist.get(0);
////
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.CALLIND, in));
////			ops.add(new PcodeOp(context.baseAddr, base, PcodeOp.CALL, in));
//
//		// invalidate argumentsCount, but don't touch the stack
//		state.setArgumentsCount(FunctionState.INVALID_ARGS);
////		}
//
//		return getPcodeOps(ops);
//		return new PcodeOp[0];
	}

//	Varnode node = context.inputlist.get(0);
////Register register = program.getRegister(node);
//
//Varnode[] in = new Varnode[1];
//in[0] = node;
//
//PcodeOp op = new PcodeOp(context.baseAddr, 0, PcodeOp.CALLIND, in);
//return new PcodeOp[] { op };

// TODO(adm244): sanity checks

// NOTE(adm244): ignore symbolic propagator call
//if (!context.inputlist.get(0).isRegister()) {
//	return new PcodeOp[0];
//}

//	Varnode[] in = new Varnode[1];
//	in[0] = context.inputlist.get(0);
//	
//	ops.add(new PcodeOp(context.baseAddr, 1, PcodeOp.CALLIND, in));
//	
//	return getPcodeOps(ops);

//	#    local _addr:4 = reg1;
//	#    local _iter:4 = 0;
//	#    local _count:4;
//	#
//	#    if (_funcArgs >= 0) goto <pre_cycle>;
//	#
//	#    _count = (1000 - _farsp) / 4;
//	#    goto <start>;
//	#
//	#    <pre_cycle>
//	#    _count = _funcArgs;
//	#
//	#    <start>
//	#    if (_iter == _count) goto <end>;
//	#
//	#    farpeek(ax, _iter);
//	#    parampush(ax);
//	#    _iter = _iter + 1;
//	#    goto <start>;
//	#
//	#    <end>
//	#    call [_addr];
//	#
//	#    paramreset();
//	#    _funcArgs = -1;

//	int base = 0;
//	
//	AddressSpace constSpace = program.getAddressFactory().getConstantSpace();
//	AddressSpace registerSpace = program.getAddressFactory().getRegisterSpace();
//	AddressSpace uniqueSpace = program.getAddressFactory().getUniqueSpace();
//	AddressSpace farStackSpace = program.getAddressFactory().getAddressSpace("farStack");
//	AddressSpace paramStackSpace = program.getAddressFactory().getAddressSpace("paramStack");
//	
//	Register regFuncArgs = program.getRegister("_funcArgs");
//	Register regFarsp = program.getRegister("_farsp");
//	Register regParamsp = program.getRegister("_paramsp");
//	
//	Varnode count = new Varnode(uniqueSpace.getAddress(2000), 4);
//	Varnode funcArgs = new Varnode(uniqueSpace.getAddress(2004), 4);
//	Varnode iter = new Varnode(uniqueSpace.getAddress(2008), 4);
//	Varnode farsp = new Varnode(uniqueSpace.getAddress(2012), 4);
//	Varnode param = new Varnode(uniqueSpace.getAddress(2016), 4);
//	Varnode paramsp = new Varnode(regParamsp.getAddress(), 4);
//	
//	Varnode out = new Varnode(uniqueSpace.getAddress(1000), 4);
//	
//	// ### 0: LOAD _funcArgs ###
//	Varnode[] in = new Varnode[2];
//	in[0] = new Varnode(constSpace.getAddress(registerSpace.getSpaceID()), 4);
//	in[1] = new Varnode(constSpace.getAddress(regFuncArgs.getOffset()), 4);
//
//	ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.LOAD, in, funcArgs));
//	
//	// ### 1: INT_SLESS _funcArgs, 0
//	Varnode[] in2 = new Varnode[2];
//	in2[0] = funcArgs;
//	in2[1] = new Varnode(constSpace.getAddress(0), 4);
//	
//	ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.INT_SLESS, in2, out));
//	
//	// ### 2: BOOL_NEGATE out
//	Varnode[] in3 = new Varnode[1];
//	in3[0] = out;
//	
//	ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.BOOL_NEGATE, in3, out));
//	
//	// ### 3: CBRANCH (_funcArgs < 0) <pre_cycle>
//	Varnode[] in4 = new Varnode[2];
//	in4[0] = new Varnode(constSpace.getAddress(5), 4);
//	in4[1] = out;
//	
//	ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.CBRANCH, in4));
//	
//		// ### 4: LOAD _farsp
//		Varnode[] in5 = new Varnode[2];
//		in5[0] = new Varnode(constSpace.getAddress(registerSpace.getSpaceID()), 4);
//		in5[1] = new Varnode(constSpace.getAddress(regFarsp.getOffset()), 4);
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.LOAD, in5, farsp));
//		
//		// ### 5: INT_SUB 1000 _farsp
//		Varnode[] in6 = new Varnode[2];
//		in6[0] = new Varnode(constSpace.getAddress(1000), 4);
//		in6[1] = farsp;
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.INT_SUB, in6, out));
//		
//		// ### 6: INT_DIV out
//		Varnode[] in7 = new Varnode[2];
//		in7[0] = out;
//		in7[1] = new Varnode(constSpace.getAddress(4), 4);
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.INT_DIV, in7, count));
//		
//		// ### 7: BRANCH <start>
//		Varnode[] in8 = new Varnode[1];
//		in8[0] = new Varnode(constSpace.getAddress(2), 4);
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.BRANCH, in8));
//		
//	// <pre_cycle>
//	// ### 8: count COPY funcArgs
//	Varnode[] in9 = new Varnode[1];
//	in9[0] = funcArgs;
//	
//	ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.COPY, in9, count));
//		
//	// <start>
//	// ### 9: INT_EQUAL iter count
//	Varnode[] in10 = new Varnode[2];
//	in10[0] = iter;
//	in10[1] = count;
//	
//	ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.INT_EQUAL, in10, out));
//	
//	// ### 10: CBRANCH (iter == count) <end>
//	Varnode[] in11 = new Varnode[2];
//	in11[0] = new Varnode(constSpace.getAddress(9), 4);
//	in11[1] = out;
//	
//	ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.CBRANCH, in11));
//	
//		//macro farpeek(x, i) {
//		//    _pos:4 = _farsp + ((i + 1) * 4);
//		//    x = *[farStack]:4 _pos;
//		//}
//		// ### 11: INT_ADD iter 1
//		Varnode[] in12 = new Varnode[2];
//		in12[0] = iter;
//		in12[1] = new Varnode(constSpace.getAddress(1), 4);
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.INT_ADD, in12, out));
//		
//		// ### 12: INT_MULT out 4
//		Varnode[] in13 = new Varnode[2];
//		in13[0] = out;
//		in13[1] = new Varnode(constSpace.getAddress(4), 4);
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.INT_MULT, in13, out));
//		
//		// ### 13: INT_ADD _farsp + out
//		Varnode[] in14 = new Varnode[2];
//		in14[0] = farsp;
//		in14[1] = out;
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.INT_ADD, in14, out));
//		
//		// ### 14: LOAD farStack out
//		Varnode[] in15 = new Varnode[2];
//		in15[0] = new Varnode(constSpace.getAddress(farStackSpace.getSpaceID()), 4);
//		in15[1] = out;
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.LOAD, in15, param));
//		
//		//macro parampush(x) {
//		//    *[paramStack]:4 _paramsp = x;
//		//    _paramsp = _paramsp - 4;
//		//}
//		// ### 15: STORE paramStack param
//		Varnode[] in16 = new Varnode[3];
//		in16[0] = new Varnode(constSpace.getAddress(paramStackSpace.getSpaceID()), 4);
//		in16[1] = paramsp;
//		in16[2] = param;
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.STORE, in16));
//		
//		// ### 16: INT_SUB _paramsp 4
//		Varnode[] in17 = new Varnode[2];
//		in17[0] = paramsp;
//		in17[1] = new Varnode(constSpace.getAddress(4), 4);
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.INT_SUB, in17, out));
//		
//		// ### 17: INT_ADD iter 1
//		Varnode[] in18 = new Varnode[2];
//		in18[0] = iter;
//		in18[1] = new Varnode(constSpace.getAddress(1), 4);
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.INT_ADD, in18, out));
//		
//		// ### 18: BRANCH <start>
//		Varnode[] in19 = new Varnode[1];
//		in19[0] = new Varnode(constSpace.getAddress(-9), 4);
//		
//		ops.add(new PcodeOp(context.baseAddr, base++, PcodeOp.BRANCH, in19));
//		
//	// <end>
//	
//	return getPcodeOps(ops);

//	AddressSpace registerSpace = program.getAddressFactory().getRegisterSpace();

	// ### dx = CPOOL(0, in[1], 5) ###
//	Varnode[] inc = new Varnode[3];
//	inc[0] = context.inputlist.get(1);
//	inc[1] = context.inputlist.get(1);
//	inc[2] = new Varnode(constSpace.getAddress(5), 4);
//
//	Register register = program.getRegister("ax");
//	Address addr = register.getAddress();
//
//	Varnode outc = new Varnode(addr, addr.getPointerSize());
//
//	ops.add(new PcodeOp(context.baseAddr, base, PcodeOp.CPOOLREF, inc, outc));

//	// ### _funcArgs = 0
//	Varnode[] in2 = new Varnode[3];
//
//	register = program.getRegister("_funcArgs");
//	in2[0] = new Varnode(constSpace.getAddress(registerSpace.getSpaceID()), 4);
//	in2[1] = new Varnode(constSpace.getAddress(register.getOffset()), 4);
//	in2[2] = new Varnode(constSpace.getAddress(0), 4);
//
//	ops.add(new PcodeOp(context.baseAddr, base + 2, PcodeOp.STORE, in2));
}

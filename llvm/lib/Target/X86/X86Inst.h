///===--- X86Inst - X86 Instruction categorization class ---===///
/// This class tests the property of MachineInstr MI
// for example isCFICMP(MI) returns true if MI is in this form:
// CMP32mi 3(%reg), $CFI_ID

// by Bin Zeng, Lehigh University CSE Dept.

#ifndef X86_INSTRUCTION_PROPERTY_H
#define X86_INSTRUCTION_PROPERTY_H

#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/MachineInstr.h"
// #include "llvm/Target/TargetInstrDesc.h"
#include "llvm/Target/TargetOpcodes.h"
#include "llvm/ADT/ilist.h"
#include "llvm/ADT/ilist_node.h"
#include "X86SFIOptPass.h"

namespace llvm{
  
  struct X86Inst{
	// returns true if MI is in this form:
	// CMP32mi 3(%reg), $(X86SFIOptPass::CFI_ID)
	static bool isCFICMP(const MachineInstr& MI);

	// return true if MI is in this form:
	// PREFETCHNTA %reg0, 0, %reg0, $CFI_ID, %reg0
	static bool isCFIID(const MachineInstr& MI);

	// return true if MI is in this form:
	// JMP_1 0
	static bool isJMP_1(const MachineInstr& MI);

	// return true if MI is TAILJMP_1, TAILJMPd, TAILJMPd64, TAILJMPm,
	// TAILJMPm64, TAILJMPr, or TAILJMPr64
	static bool isTAILJMP(const MachineInstr& MI);

	// return true if MBB is the error label MBB
	// which contains only one instruction: JMP_1 0
	static bool isErrorLabel(const MachineBasicBlock& MBB);
	
	// return true if MI is a prefetch instruction:
	// PREFETCHNTA, PREFETCHT0, PREFETCHT1, PREFETCHT2
	static bool isPrefetch(const MachineInstr& MI);

	// returns true if MI is in this form:
	// AND32ri %reg, $DATA_MASK
	static bool isDataMask(const MachineInstr& MI);

	// returns true if MI is in this form:
	// AND32ri %reg, $CODE_MASK
	static bool isCodeMask(const MachineInstr& MI);

	// return the index of the first MachineOperand
	// that constitues the memory location of MI
	// if there is no such MachineOperand, return -1
	static int getMemIndex(const MachineInstr& MI);

	// return true if MI is a push or pop instruction
	static bool isPushPop(const MachineInstr& MI);
	
	// returns true if MI is a push instruction that
	// does not push memory operands: PUSH32r, PUSH16r...
	static bool isPushOnly(const MachineInstr& MI);

	// returns true if MI is a memory push instruction
	// that pushes a memory operand onto stack:
	// PUSH16rmm, PUSH32rmm and so on
	static bool isPushMem(const MachineInstr& MI); 

	// returns true if MI is a pop instruction that
	// does not pop memory operands: POP32r, POP16r...
	static bool isPopOnly(const MachineInstr& MI);
	
	// returns true if MI is a pop instruction that
	// pops from stack to a memory location such as:
	// POP16rmm, POP32rmm and so on
	static bool isPopMem(const MachineInstr& MI);

	// returns true if MI only loads and it does not
	// store to a memory location
	static bool isLoadOnly(const MachineInstr& MI);

	// returns true if MI only stores and it does not
	// load from a memory location
	static bool isStoreOnly(const MachineInstr& MI);

	// return true if MI has a memory index, i.e.
	// MI has operands like [base, scale, index, disp, seg]
	static bool hasMemIndex(const MachineInstr& MI);

	// return true if MI uses a register to compute memory location
	// memIndex is the index of the first MachineOperand that
	// constitues a memory location
	static bool indirectLoadStore(const MachineInstr& MI,
								  const int memIndex);
	// print out the OperandInfo of MI
	static void printOperandInfo(const MachineInstr& MI);
	
	// return the super register of X86 register reg
	static unsigned getSuperReg(const unsigned reg, const TargetRegisterInfo* TRI);

	// returns true if MI1 and MI2 are indepent. i.e. they can be reordered
	// if one of them loads from memory and the other stores to memory
	// or both of them store to memory. or one of them reads a register, and
	// the other writes to the register, or both of them write to the same register
	// then return false; else return true;
	static bool independent(const MachineInstr& MI1, const MachineInstr& MI2);

	// return true if MachineLoop ML has subLoops
	static bool hasSubLoops(const MachineLoop& ML);

	// dump the CFG of MF
	static void dumpCFG(const MachineFunction& MF);

	// return the index of the first non-zero bit in a
	// e.g. 1 returns 0. 2 returns 1. 0 returns -1
	static int getFirstNonZeroBit(unsigned a);
  };
}

#endif

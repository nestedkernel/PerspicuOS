///===--- X86SFIOptPass - Software Fault Isolation optimization pass ---===///
// By Bin Zeng, Lehigh University CSE Dept.

#ifndef X86SFIOPTPASS_H
#define X86SFIOPTPASS_H

#include "llvm/CodeGen/MachineFunctionPass.h"
#include "X86TargetMachine.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/MachineDominators.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/PseudoSourceValue.h"
#include "llvm/Target/TargetRegisterInfo.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

namespace llvm {
  class MachineBasicBlock;
  class MachineInstr;
  class DebugLoc;
  class TargetInstrInfo;
  class MachineFunction;

  struct X86SFIOptPass: public MachineFunctionPass {

    X86TargetMachine &TM; // the X86 target machine;
    static char ID; // the ID of the pass

	// the tag of the sandbox, which is bit pattern
	// all the data region should share
	//            SFI_LARGE    SFI_MEDIUM   SFI_CLASSIC
	// CODE_START 0x90000000U  0x10000000U  0x10000000U
	// CODE_SIZE  0x01000000U  0x01000000U  0x01000000U
	// DATA_START 0x40000000U  0x20000000U  0x20000000U
	// DATA_SIZE  0x40000000U  0x08000000U  0x01000000U
	// DATA_MASK  0x7fffffffU  0x27ffffffU  0x20ffffffU
	// JUMP_MASK  0x90fffff0U  0x10fffff0U  0x10fffff0U

	const static unsigned BOTTOM       = 0x00000000UL;
	const static unsigned TOP          = 0xffffffffUL;
	const static unsigned CODE_START   = 0x90000000UL;
	const static unsigned CODE_END     = 0x90ffffffUL;
	const static unsigned DATA_START   = 0x40000000UL;
	const static unsigned DATA_END     = 0x7fffffffUL;
	const static unsigned CODE_MASK    = 0x90ffffffUL;
	const static unsigned DATA_MASK    = 0x7fffffffUL;
	const static unsigned GUARD_REGION = /*0x00001000UL*/ 0x00500000UL;
	const static unsigned CODE_BOTTOM  = CODE_START - GUARD_REGION;
	const static unsigned CODE_TOP     = CODE_END   + GUARD_REGION;
	const static unsigned DATA_BOTTOM  = DATA_START - GUARD_REGION;
	const static unsigned DATA_TOP     = DATA_END   + GUARD_REGION;

	unsigned numPushf;
	unsigned numPushs;
	unsigned numAnds;

	const static bool allPushf      = false;  // if true, insert pushf everywhere
	const static bool useDeadRegs   = true;   // if true, use dead registers
	const static bool sandboxLoads  = true;  // if true, sandbox loads and stores
	const static bool onsiteSandbox = true;  // if true, do onsite sandboxing

	const TargetInstrInfo *TII;
	const TargetRegisterInfo *TRI;

	bool Changed; // true if loop is changed.
	bool FirstInLoop; // True if it's the first LICM in the loop
	MachineLoop *CurLoop;
	MachineBasicBlock *CurPreheader; // The preheader for CurLoop

	BitVector AllocatableSet;

	static bool isCFICMP(const MachineInstr& MI);
	
  X86SFIOptPass(X86TargetMachine &tm) : MachineFunctionPass(ID), TM(tm),
	  numPushf(0), numPushs(0), numAnds(0) {}

  virtual const char *getPassName() const;

  virtual void getAnalysisUsage(AnalysisUsage &AU) const;

	virtual bool runOnMachineFunction(MachineFunction& F);

  // Flag whether we're compiling for 32-bit or 64-bit x86
  bool is64Bit(void) {
    return TM.getSubtarget<X86Subtarget>().is64Bit();
  }

  void insertPushf (MachineInstr* MI, DebugLoc& dl, const TargetInstrInfo* TII);
  void insertPopf  (MachineInstr* MI, DebugLoc& dl, const TargetInstrInfo* TII);

	// find a dead register right before MI
	// a dead register is one that does not live in to MI
	// if there is one dead register returns it, else returns 0
	// MI is a store instruction, idx is the index of the first
	// MachineOperand that constitutes the memory location
	static unsigned findDeadReg(const MachineInstr* MI, const unsigned idx);

	// insert a mask instruction before store instruction MI
	// this version does not use any dead registers
	void insertMaskBeforeStoreNoDead(MachineBasicBlock& MBB, MachineInstr* MI,
									 DebugLoc& dl, const TargetInstrInfo* TII,
									 const unsigned memIndex);
	
	// insert a mask instruction before store instruction MI
    // if MI does not need a mask instruction, do nothing
	// else insert mask instructions right before MI
	// MI->getOperand(memIndex) throught MI->getOperand(memIndex+4)
	// should constitute a memory location
	void insertMaskBeforeStore(MachineBasicBlock& MBB, MachineInstr* MI,
							   DebugLoc& dl, const TargetInstrInfo* TII,
							   const unsigned memIndex);

	// insert a mask instruction before store instruction MI using dead register
	// if useDead is true, use dead registers
	// if pushf is true, pushf at each sandboxing 
	void insertMaskBeforeStore(MachineBasicBlock& MBB, MachineInstr* MI,
							   DebugLoc& dl, const TargetInstrInfo* TII,
							   const unsigned memIndex,
							   const bool useDead, const bool pushf);


	// insert sandboxing instructions right after MI to sandbox %ebp
	// MI should modify %ebp
	// we only sandbox the change to %ebp so that
	// there is no need to sandbox all the uses of %ebp
	void insertMaskAfterReg(MachineBasicBlock& MBB, MachineInstr* MI,
								   DebugLoc& dl, const TargetInstrInfo* TII,
								   const unsigned Reg, const bool pushf);
	
	// insert sandboxing instructions right after MI to sandbox %esp
	// MI must modify %esp. we only sandbox the change to %esp so that
	// there is no need to sandbox all the uses of %esp
	static void insertMaskAfterReg(MachineBasicBlock& MBB, MachineInstr* MI,
								   DebugLoc& dl, const TargetInstrInfo* TII,
								   const unsigned Reg);
	
	//return true if sandboxing MI needs to save EFLAGS on stack
    static bool needsPushf(const MachineInstr* const MI, const TargetRegisterInfo* TRI);

	// returns the instruction which defines the register reg by walking up the
	// basic block from and on instruction MI
	static MachineInstr* getDefInst(MachineInstr& MI, const unsigned reg);
	
	// returns true if MI refers to a variable on stack
	// index is the index of the first MachineOperand
	// constituting the mem location operand
	// returns true if MI refers to memory on stack
	static bool onStack(const MachineInstr* MI, const unsigned index);

	// returns true if MI uses only base reg to calculate the memory location
	// for example, (%eax), (%ebx) and so on
	static bool baseReg2Mem(const MachineInstr* const MI, const unsigned memIndex);


	//====================================================================================
	// These are load related methods
	
	// insert andl instrution before the load instruction,
	// MBB is the MachineBasicBlock MI belongs to. MI is the load instruction
	// memIndex is the index of the first MachineOperand that constitutes
	// the memory loc
	void insertMaskBeforeLoad(MachineBasicBlock& MBB, MachineInstr* MI,
							  DebugLoc& dl, const TargetInstrInfo* TII,
							  const unsigned memIndex);

	// insert andl instruction before the load instruction
	// similar to the function above
	void insertMaskBeforeLoad(MachineBasicBlock& MBB, MachineInstr* MI,
							  DebugLoc& dl, const TargetInstrInfo* TII,
							  const unsigned memIndex,
							  const bool useDead, const bool pushf);

	// insert andl instruction before CMP32mi $CFI_ID, 3(%reg)
	void insertMaskBeforeCheck(MachineBasicBlock &MBB, MachineInstr *MI,
							   DebugLoc& dl, const TargetInstrInfo* TII,
							   const unsigned memIndex);
	
	// insert sandboxing instructions before Jmp32m instruction
	void insertMaskBeforeJMP32m(MachineBasicBlock& MBB, MachineInstr* MI,
								DebugLoc& dl, const TargetInstrInfo* TII,
								const unsigned memIndex);

	// return the index of the first MachineOperand that constitutes a
	// memory location MI should be a load or store instruction that
	// visits memory 
	static unsigned getMemIndex(const MachineInstr* const MI);

	// sandbox REP_MOVSX instructions
	// REP_MOVS instructions move byte from address DS:(E)SI to ES:(E)DI
	void insertMaskBeforeREP_MOVSX(MachineBasicBlock& MBB, MachineInstr* MI,
								 DebugLoc& dl, const TargetInstrInfo* TII);

	// sandbox CALL32m instruction
	void insertMaskBeforeCALL32m(MachineBasicBlock& MBB, MachineInstr* MI,
								 DebugLoc& dl, const TargetInstrInfo* TII,
								 const unsigned memIndex);

	// sandbox TAILJMPm
	void insertMaskBeforeTAILJMPm(MachineBasicBlock& MBB, MachineInstr* MI,
								  DebugLoc& dl, const TargetInstrInfo* TII,
								  const unsigned memIndex);
  };
}

#endif

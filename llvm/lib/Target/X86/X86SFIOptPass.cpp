///===----- X86SFIOptPass - Software Fault Isolation optimization pass ----===//
//
//                     Control-Flow Integrity Implementation
//
// This file was written by Bin Zeng at the Lehigh University CSE Department.
// All Right Reserved.
//
// This file contains code written by John Criswell at the University of
// Illinois at Urbana-Champaign.
//
//===----------------------------------------------------------------------===//
//
// This file implements a machine language level transform that enforces
// software fault isolation for SVA.
//
//===----------------------------------------------------------------------===//

#include "X86.h"
#include "X86SFIOptPass.h"
#include "X86CFIOptPass.h"
#include "llvm/Pass.h"
#include "llvm/Function.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/ADT/ilist.h"
#include "llvm/ADT/ilist_node.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/DenseMapInfo.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/DebugLoc.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/ADT/BitVector.h"
#include "X86Inst.h"

using namespace llvm;

char X86SFIOptPass::ID = 0;

//
// Function: isStackPointer()
//
// Description:
//  Determine if this register is the stack pointer.
//
static inline bool
isStackPointer (unsigned Reg) {
  return ((Reg == X86::ESP) || (Reg == X86::RSP));
}

static inline bool
isFramePointer (unsigned Reg) {
  return ((Reg == X86::EBP) || (Reg == X86::RBP));
}

void X86SFIOptPass::insertPushf (MachineInstr* nextMI,
                                 DebugLoc& dl,
                                 const TargetInstrInfo* TII) {
  MachineBasicBlock & MBB = *nextMI->getParent();
  if (is64Bit ())
    BuildMI (MBB, nextMI, dl, TII->get(X86::PUSHF64));
  else
    BuildMI (MBB, nextMI, dl, TII->get(X86::PUSHF32));
  return;
}

void X86SFIOptPass::insertPopf (MachineInstr* nextMI,
                                DebugLoc& dl,
                                const TargetInstrInfo* TII) {
  MachineBasicBlock & MBB = *nextMI->getParent();
  if (is64Bit ())
    BuildMI (MBB, nextMI, dl, TII->get(X86::POPF64));
  else
    BuildMI (MBB, nextMI, dl, TII->get(X86::POPF32));
  return;
}

const char* X86SFIOptPass::getPassName() const { return "X86 SFI optimizer"; }

void X86SFIOptPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.setPreservesCFG();
  MachineFunctionPass::getAnalysisUsage(AU);
}

// return true if MI is in this form:
// CMP32mi 3(%reg), $CFI_ID
bool X86SFIOptPass::isCFICMP(const MachineInstr& MI){
  return X86Inst::isCFICMP(MI);
}  

// Idx is the index of the first MachineOperand that constitutes the memory
// location the instruction MI will store to
// e.g. movl %eax, 4(%ebx, %ecx, 4)
// if this instruction kills %ecx, then we can use %ecx for sandboxing
unsigned X86SFIOptPass::findDeadReg(const MachineInstr* MI, unsigned Idx){
#if 0
  const TargetRegisterInfo* TRI = MI->getParent()->getParent()->getTarget().getRegisterInfo();
  unsigned dead = 0;
  BitVector liveIns = MI->getLiveIns();
  // find a Reg that does not live in to MI
  if(!liveIns[X86::AH] && !liveIns[X86::AL] && !liveIns[X86::AX] && !liveIns[X86::EAX])
	dead = X86::EAX;
  else if(!liveIns[X86::CH] && !liveIns[X86::CL] && !liveIns[X86::CX] && !liveIns[X86::ECX])
	dead = X86::ECX;
  else if(!liveIns[X86::DH] && !liveIns[X86::DL] && !liveIns[X86::DX] && !liveIns[X86::EDX])
	dead = X86::EDX;
  else if(!liveIns[X86::BH] && !liveIns[X86::BL] && !liveIns[X86::BX] && !liveIns[X86::EBX])
  	dead = X86::EBX;
  else if(!liveIns[X86::SI] && !liveIns[X86::ESI])
  	dead = X86::ESI;
  else if(!liveIns[X86::DI] && !liveIns[X86::EDI])
	dead = X86::EDI;
  else {
	// find a Reg that lives in to MI and is only used to calculate the
	// memory location and it is killed by MI.e.g. movl %eax, 4(%ebx, %ecx, 4)
	// if %ebx is killed by movl and only used to calculate the memory location
	// we can use it for sandboxing
	BitVector kills = MI->getKills();
	unsigned BaseReg = MI->getOperand(Idx).getReg();
	if(BaseReg && kills[BaseReg]){ // test whether BaseReg is used twice
	  // there are some corner cases like this:
	  // mov %eax, 24(%eax, %ecx)
	  // even if %eax is skill by mov, it still can not be used for sandboxing
	  // because its value will be changed if we use it for sandboxing
	  bool useTwice = false;
	  for(unsigned index=0; index < Idx; ++index){
		const MachineOperand& MO = MI->getOperand(index);
		if(MO.isReg() && MO.getReg()){
		  if(TRI->regsOverlap(BaseReg, MO.getReg())){
			useTwice = true;
			break;
		  }
		}
	  }
	  if(!useTwice){
		for(unsigned index=Idx+5, end=MI->getNumOperands(); index<end; ++index){
		  const MachineOperand& MO = MI->getOperand(index);
		  if(MO.isReg() && MO.getReg()){
			if(TRI->regsOverlap(BaseReg, MO.getReg())){
			  useTwice = true;
			  break;
			}
		  }
		}
	  }
	  // if(!useTwice) dead = BaseReg;
	  // test whether any of BaseReg's subregisters are killed also
		if(!useTwice){
		  unsigned SubReg;
		for(const unsigned *SubRegs = TRI->getSubRegisters(BaseReg);
			(SubReg = *SubRegs); ++SubRegs)
		  if(!kills[SubReg]) abort(); // if BaseReg is skilled, so should its subReg
		if(!SubReg) dead = BaseReg;
	  }
	} else { // test whether IndexReg is used twice
	  unsigned IndexReg = MI->getOperand(Idx+2).getReg();
	  if(IndexReg && kills[IndexReg]){
		bool useTwice = false;
		for(unsigned index=0; index < Idx; ++index){
		  const MachineOperand& MO = MI->getOperand(index);
		  if(MO.isReg() && MO.getReg()){
			unsigned Reg = MO.getReg();
			if(TRI->regsOverlap(IndexReg, Reg)){
			  useTwice = true;
			  break;
			}
		  }
		}
		if(!useTwice){
		  for(unsigned index=Idx+5, end=MI->getNumOperands(); index<end; ++index){
			const MachineOperand& MO = MI->getOperand(index);
			if(MO.isReg() && MO.getReg()){
			  unsigned Reg = MO.getReg();
			  if(TRI->regsOverlap(IndexReg, Reg)){
				useTwice = true;
				break;
			  }
			}
		  }
		}
		// if(!useTwice) dead = IndexReg;
		if(!useTwice){
		  unsigned SubReg;
		  for(const unsigned *SubRegs = TRI->getSubRegisters(IndexReg);
			  (SubReg = *SubRegs); ++SubRegs)
			if(!kills[SubReg]) abort();
		  if(!SubReg) dead = IndexReg;
		}
	  }
	}
  }
  return dead;
#else
  return 0;
#endif
}

// returns true if MI refers to memory location on stack
bool X86SFIOptPass::onStack(const MachineInstr* MI, const unsigned index) {
  //
  // If the memory operand uses %ebp, %esp, %rbp, or %rsp as a base register
  // and an immediate value as displacement (e.g., movl %ecx, 8(%ebp)), then
  // do not mask it.
  //
  // TODO: Figure out how much of an offset we can handle.
  //
  unsigned base = MI->getOperand(index).getReg(); // base reg
  if ((isStackPointer (base)) || (isFramePointer (base))) {
    if (MI->getOperand(index+1).getImm() == 1 &&     // scale value
        MI->getOperand(index+2).getReg() == 0 &&     // index reg
        MI->getOperand(index+3).isImm() &&
        MI->getOperand(index+3).getImm() < GUARD_REGION && // displacement value
        MI->getOperand(index+4).getReg() == 0)             // segment reg
      return true;
  }

  return false;
}

//
// Description:
//  Determine if the specified machine instruction will need the processor
//  flags (eflags) saved after it is sandboxed.
//
// Inputs:
//  MI - The machine instruction to check.  It should be a store or the
//       instruction right after the andl/andq.
//
// Return value:
//  true - The processor flags need to be saved.
//  false - The processor flags do not need to be saved.
//
bool X86SFIOptPass::needsPushf(const MachineInstr* const MI,
                               const TargetRegisterInfo* TRI) {
  //
  // If the instruction uses the processor flags register directly, then it
  // must be saved.
  //
  if (MI->readsRegister(X86::EFLAGS, TRI))
    return true;

  //
  // If the instruction modifies the processor flags register, then no saving
  // is required.
  //
  if (MI->definesRegister(X86::EFLAGS, TRI) ||
      MI->modifiesRegister(X86::EFLAGS, TRI))
    return false;

  //
  // Examine all instructions following the specified instruction.  If any of
  // them define or modify the processor flags, then we do not need to save the
  // processor status register.  If something uses the processor status
  // register, then we do.
  //
  const MachineBasicBlock& MBB = *MI->getParent();
  MachineBasicBlock::const_iterator I = MBB.begin(), E = MBB.end();
  while (I != E && &*I != MI) ++I;
  if (&*I == MI) ++I;
  bool need = false; // true;
  while (I != E) {
    if ((*I).definesRegister(X86::EFLAGS, TRI) ||
        (*I).modifiesRegister(X86::EFLAGS, TRI)) {
      need = false;
      break;
    } else if ((*I).readsRegister(X86::EFLAGS, TRI)) {
      need = true;
      break;
    }

    ++I;
  }

  return need;
}

//
// Description:
//  Return the instruction which defines the specified register by walking up
//  the basic block from an instruction MI.
//
MachineInstr* X86SFIOptPass::getDefInst(MachineInstr& MI, const unsigned reg){
  //
  // Scan backwards through the basic block looking for the specified
  // instruction.
  //
  MachineBasicBlock& MBB = *MI.getParent();
  const TargetRegisterInfo* TRI=MBB.getParent()->getTarget().getRegisterInfo();
  MachineBasicBlock::reverse_iterator CRI = MBB.rbegin(), CRE = MBB.rend();
  while(CRI != CRE && &*CRI != &MI) ++CRI;

  //
  // Scan backwards from the instruction looking for an instruction that
  // either modifies or defines the register.  If we find such an instruction,
  // return it.
  //
  while (CRI != CRE) {
    if ((*CRI).modifiesRegister(reg, TRI) || (*CRI).definesRegister(reg, TRI))
      return &*CRI;
    ++CRI;
  }

  //
  // We did not find the defining instruction.
  //
  return 0;
}

// returns true if MI uses only a base register to get a memory location such as in (%eax)
bool X86SFIOptPass::baseReg2Mem(const MachineInstr* const MI, const unsigned index){
  return (MI->getOperand(index).getReg()   != 0 &&
		  MI->getOperand(index+1).getImm() == 1 &&
		  MI->getOperand(index+2).getReg() == 0 &&
		  MI->getOperand(index+3).isImm() &&
		  MI->getOperand(index+3).getImm() < GUARD_REGION &&
		  MI->getOperand(index+4).getReg() == 0);
}

//
// Description:
//  Insert sandboxing instructions right after the specified instruction to
//  sandbox the specified register.
//
// Inputs:
//  MI - The machine instruction which should modify the specified register.
//  Reg - The register which is modified by the machine instruction.
//
void X86SFIOptPass::insertMaskAfterReg (MachineBasicBlock& MBB,
                                        MachineInstr* MI,
                                        DebugLoc& dl,
                                        const TargetInstrInfo* TII,
                                        const unsigned Reg,
                                        const bool pushf) {
  const TargetRegisterInfo* TRI=MBB.getParent()->getTarget().getRegisterInfo();

  //
  // Find the instruction following the specified instruction within the basic
  // block (if such an instructions exists).
  //
  MachineBasicBlock::iterator NXT = MBB.begin(), end = MBB.end();
  while (NXT != end && &*NXT != MI) ++NXT;
  if (NXT != end) ++NXT;
  MachineInstr* nextMI = &*NXT;

  //
  // If the specified instruction is the last instruction in the basic block,
  // then we know that we do not need to save the processor status flags.
  // Otherwise, go find out if we need to save the processor status flags.
  //
  // TODO: Verify if this is correct.
  //
  bool saveFlags = (NXT == end) ?  false : needsPushf(nextMI, TRI);

  if (isStackPointer(Reg) && saveFlags) {
    MachineInstr* Def = getDefInst(*MI, X86::EFLAGS);
    assert (Def && "Error can not find the instruction which defines eflags\n");
    assert ((Def != MI) && "Error: MI defines %%esp and eflags\n");
    MachineInstr* next = Def->getNextNode();
    bool independent = true;
    while (next != MI) {
      if (!X86Inst::independent(*Def, *next)) {
        independent = false;
        break;
      }
      next = next->getNextNode();
    }

    if(!independent){
      llvm::errs() << "Error: the instruction which defines eflags can not be moved\n";
      abort();
    }

    //
    // Create an instruction that creates a version of the pointer with the
    // proper bits set.
    //
    MachineInstr * maskedPtr = BuildMI (MBB,
                                        nextMI,
                                        dl,
                                        TII->get(X86::OR32ri),
                                        Reg).addReg(Reg).addImm(setMask);

    //
    // Create an instruction to mask off the proper bits to see if the pointer
    // is within the secure memory range.
    //
    // AND32ri %Reg, DATA_MASK
    //
    MachineInstr * checkMasked = BuildMI (MBB,
                                          nextMI,
                                          dl,
                                          TII->get(X86::AND32ri),
                                          Reg).addReg(Reg).addImm(setMask);

    //
    // Compare the masked pointer to the mask.  If they're the same, we need to
    // set that bit.
    //
    BuildMI(MBB,nextMI,dl, TII->get(X86::AND32ri), Reg).addReg(Reg).addImm(DATA_MASK);
    // make a copy of Def
    const MachineInstrBuilder& MIB = BuildMI(MBB, nextMI, dl, TII->get(Def->getOpcode()));
    for(unsigned i = 0, e = Def->getNumOperands(); i < e; ++i)
      MIB.addOperand(Def->getOperand(i));
    Def->eraseFromParent(); // delete Def
    return;
  }

  //
  // Insert code to save the processor status flags if needed.
  //
  if (pushf || saveFlags)
    insertPushf(nextMI,dl,TII);

  // AND32ri %Reg, DATA_MASK
  BuildMI(MBB,nextMI,dl,TII->get(X86::AND32ri),Reg).addReg(Reg).addImm(DATA_MASK);

  //
  // Insert code to restore the processor flags if necesary.
  //
  if (pushf || saveFlags)
    insertPopf (nextMI,dl,TII);
  return;
}

#if 0
void X86SFIOptPass::insertMaskAfterReg(MachineBasicBlock& MBB, MachineInstr* MI,
									   DebugLoc& dl, const TargetInstrInfo* TII,
									   const unsigned Reg){
  insertMaskAfterReg(MBB, MI, dl, TII, Reg, allPushf);  // use pushf
}

void X86SFIOptPass::insertMaskBeforeStore(MachineBasicBlock& MBB, MachineInstr* MI,
										 DebugLoc& dl, const TargetInstrInfo* TII,
										 const unsigned memIndex){
  insertMaskBeforeStore(MBB,MI,dl,TII,memIndex,useDeadRegs,allPushf);
}

// insert sandboxing instructions right before MI
void X86SFIOptPass::insertMaskBeforeStore(MachineBasicBlock& MBB, MachineInstr* MI,
										  DebugLoc& dl, const TargetInstrInfo* TII,
										  const unsigned memIndex,
										  const bool useDead, const bool pushf){
  assert(MI->getDesc().mayStore() && "store instruction expected");
  const TargetRegisterInfo* TRI = MI->getParent()->getParent()->getTarget().getRegisterInfo();
  if(!X86Inst::indirectLoadStore(*MI, memIndex)) return;
  if(onStack(MI, memIndex)) return;
  // if MI is in this form: movl %eax, (%ebx),sandbox %ebx
  if(onsiteSandbox && baseReg2Mem(MI, memIndex)) {
	unsigned base = MI->getOperand(memIndex).getReg();
	bool saveFlags = needsPushf(MI,TRI);
	if(pushf || saveFlags) BuildMI(MBB,MI,dl,TII->get(X86::PUSHF32)); // PUSHF32
	//andl &DATA_MASK, %base
	BuildMI(MBB,MI,dl,TII->get(X86::AND32ri),base).addReg(base).addImm(DATA_MASK);
	if(pushf || saveFlags) BuildMI(MBB,MI,dl,TII->get(X86::POPF32)); // POPF32
	++numAnds; return;
  }
  bool saved = false;
  unsigned dead = 0;
  if(useDead) dead = findDeadReg(MI, memIndex);
  if(dead == 0){ // no free register, we have to spill one onto stack
	if(MI->readsRegister(X86::SP, TRI)    || MI->readsRegister(X86::ESP, TRI) ||
	   MI->modifiesRegister(X86::SP, TRI) || MI->modifiesRegister(X86::ESP, TRI)) abort();
	if(!MI->readsRegister(X86::AH, TRI) && !MI->readsRegister(X86::AL,  TRI) &&
	   !MI->readsRegister(X86::AX, TRI) && !MI->readsRegister(X86::EAX, TRI) &&
	   !MI->modifiesRegister(X86::EAX, TRI))
	  dead = X86::EAX;
	else if(!MI->readsRegister(X86::BH, TRI) && !MI->readsRegister(X86::BL,  TRI) &&
			!MI->readsRegister(X86::BX, TRI) && !MI->readsRegister(X86::EBX, TRI) &&
			!MI->modifiesRegister(X86::EBX, TRI))
	  dead = X86::EBX;
	else if(!MI->readsRegister(X86::CH, TRI) && !MI->readsRegister(X86::CL,  TRI) &&
			!MI->readsRegister(X86::CX, TRI) && !MI->readsRegister(X86::ECX, TRI) &&
			!MI->modifiesRegister(X86::ECX, TRI))
	  dead = X86::ECX;
	else if(!MI->readsRegister(X86::DH, TRI) && !MI->readsRegister(X86::DL,  TRI) &&
			!MI->readsRegister(X86::DX, TRI) && !MI->readsRegister(X86::EDX, TRI) &&
			!MI->modifiesRegister(X86::EDX, TRI))
	  dead = X86::EDX;
	else if(!MI->readsRegister(X86::SI, TRI) && !MI->readsRegister(X86::ESI, TRI) &&
			!MI->modifiesRegister(X86::ESI, TRI))
	  dead = X86::ESI;
	else if(!MI->readsRegister(X86::DI, TRI) && !MI->readsRegister(X86::EDI, TRI) &&
			!MI->modifiesRegister(X86::EDI, TRI))
	  dead = X86::EDI;
	else abort();
	BuildMI(MBB,MI,dl,TII->get(X86::PUSH32r)).addReg(dead); // pushl %dead
	saved = true;
	++numPushs;
  }
  // leal mem_loc, %dead
  const MachineInstrBuilder& LEA =
	BuildMI(MBB,MI,dl,TII->get(X86::LEA32r),dead)
	.addOperand(MI->getOperand(memIndex+0))
	.addOperand(MI->getOperand(memIndex+1))
	.addOperand(MI->getOperand(memIndex+2))
	.addOperand(MI->getOperand(memIndex+3)); 
  for(MachineInstr::mmo_iterator MMI = MI->memoperands_begin(),
		MME = MI->memoperands_end(); MMI != MME; ++MMI)
	LEA.addMemOperand(*MMI);
  bool saveFlags = needsPushf(MI,TRI);
  if(pushf || saveFlags) { ++numPushf; BuildMI(MBB,MI,dl,TII->get(X86::PUSHF32)); }
  //andl &DATA_MASK, %dead
  BuildMI(MBB,MI,dl,TII->get(X86::AND32ri),dead).addReg(dead).addImm(DATA_MASK); 
  ++numAnds;
  if(pushf || saveFlags) BuildMI(MBB,MI,dl,TII->get(X86::POPF32)); // POPF32
  // insert a store instruction so that it uses %dead as the base reg
  const MachineInstrBuilder& MIB = BuildMI(MBB,MI,dl,MI->getDesc());
  for(unsigned i = 0; i < memIndex; ++i)
	MIB.addOperand(MI->getOperand(i));  
  MIB.addReg(dead).addImm(1).addReg(0).addImm(0).addReg(0);
  for(unsigned i = memIndex+5, end = MI->getNumOperands(); i < end; ++i)
	MIB.addOperand(MI->getOperand(i));
  if(saved) BuildMI(MBB,MI,dl,TII->get(X86::POP32r),dead); // popl %dead
  MI->eraseFromParent();
}

void X86SFIOptPass::insertMaskBeforeCheck(MachineBasicBlock& MBB, MachineInstr* MI,
										  DebugLoc& dl, const TargetInstrInfo* TII,
										  const unsigned memIndex){
  assert(MI->getOpcode() == X86::CMP32mi);
  const unsigned Reg = MI->getOperand(0).getReg();
  // AND32ri %reg, $CODE_MASK
  BuildMI(MBB,MI,dl,TII->get(X86::AND32ri),Reg).addReg(Reg).addImm(CODE_MASK);
}

//================================================================================
// these are the load related methods

void X86SFIOptPass::insertMaskBeforeLoad(MachineBasicBlock& MBB, MachineInstr* MI,
										 DebugLoc& dl, const TargetInstrInfo* TII,
										 const unsigned memIndex){
  if(sandboxLoads) insertMaskBeforeLoad(MBB,MI,dl,TII,memIndex,useDeadRegs,allPushf);
}

// insert sandboxing instructions before load
void X86SFIOptPass::insertMaskBeforeLoad(MachineBasicBlock& MBB, MachineInstr* MI,
										 DebugLoc& dl, const TargetInstrInfo* TII,
										 const unsigned memIndex,
										 const bool useDead, const bool pushf){
  assert(MI->getDesc().mayLoad() && "load instruction expected");
  const TargetRegisterInfo* TRI = MI->getParent()->getParent()->getTarget()
	.getRegisterInfo();
  if(onStack(MI, memIndex)) return;
  // no need to sandbox direct memory access
  if(!X86Inst::indirectLoadStore(*MI, memIndex)) return; 
  // if MI is in this form: movl 4(%eax), %ebx, sandbox %eax directly
  if(onsiteSandbox && baseReg2Mem(MI, memIndex)) { 
	unsigned base = MI->getOperand(memIndex).getReg();
	bool saveFlags = needsPushf(MI,TRI);
	if(pushf || saveFlags) BuildMI(MBB,MI,dl,TII->get(X86::PUSHF32)); // PUSHF32
	//andl &DATA_MASK, %base
	BuildMI(MBB,MI,dl,TII->get(X86::AND32ri),base).addReg(base).addImm(DATA_MASK);
	if(pushf || saveFlags) BuildMI(MBB,MI,dl,TII->get(X86::POPF32)); // POPF32
	++numAnds; return;
  }
  bool saved = false;
  unsigned dead = 0;
  if(useDead) dead = findDeadReg(MI, memIndex);
  // TODO MI can change %dead
  if(dead == 0){ // no free register, we have to spill one onto stack
	if(MI->readsRegister(X86::SP, TRI) || MI->readsRegister(X86::ESP, TRI))
	  abort();
	if(!MI->readsRegister(X86::AH, TRI) && !MI->readsRegister(X86::AL,  TRI) &&
	   !MI->readsRegister(X86::AX, TRI) && !MI->readsRegister(X86::EAX, TRI) &&
	   !MI->modifiesRegister(X86::EAX, TRI))
	  dead = X86::EAX;
	else if(!MI->readsRegister(X86::BH, TRI) && !MI->readsRegister(X86::BL,  TRI) &&
			!MI->readsRegister(X86::BX, TRI) && !MI->readsRegister(X86::EBX, TRI) &&
			!MI->modifiesRegister(X86::EBX, TRI))
	  dead = X86::EBX;
	else if(!MI->readsRegister(X86::CH, TRI) && !MI->readsRegister(X86::CL,  TRI) &&
			!MI->readsRegister(X86::CX, TRI) && !MI->readsRegister(X86::ECX, TRI) &&
			!MI->modifiesRegister(X86::ECX, TRI))
	  dead = X86::ECX;
	else if(!MI->readsRegister(X86::DH, TRI) && !MI->readsRegister(X86::DL,  TRI) &&
			!MI->readsRegister(X86::DX, TRI) && !MI->readsRegister(X86::EDX, TRI) &&
			!MI->modifiesRegister(X86::EDX, TRI))
	  dead = X86::EDX;
	else if(!MI->readsRegister(X86::SI, TRI) && !MI->readsRegister(X86::ESI, TRI) &&
			!MI->modifiesRegister(X86::ESI, TRI))
	  dead = X86::ESI;
	else if(!MI->readsRegister(X86::DI, TRI) && !MI->readsRegister(X86::EDI, TRI) &&
			!MI->modifiesRegister(X86::EDI, TRI))
	  dead = X86::EDI;
	else abort();
	BuildMI(MBB,MI,dl,TII->get(X86::PUSH32r)).addReg(dead); // pushl %dead
	saved = true;
	++numPushs;
  }
  // leal mem_loc, %dead
  const MachineInstrBuilder& LEA =
	BuildMI(MBB,MI,dl,TII->get(X86::LEA32r),dead)
	.addOperand(MI->getOperand(memIndex+0))
	.addOperand(MI->getOperand(memIndex+1))
	.addOperand(MI->getOperand(memIndex+2))
	.addOperand(MI->getOperand(memIndex+3)); 
  for(MachineInstr::mmo_iterator MMI = MI->memoperands_begin(),
		MME = MI->memoperands_end(); MMI != MME; ++MMI)
	LEA.addMemOperand(*MMI);
  bool saveFlags = needsPushf(MI,TRI);
  if(pushf || saveFlags) { ++numPushf; BuildMI(MBB,MI,dl,TII->get(X86::PUSHF32)); }
  //andl &DATA_MASK, %dead
  BuildMI(MBB,MI,dl,TII->get(X86::AND32ri),dead).addReg(dead).addImm(DATA_MASK); 
  ++numAnds;
  if(pushf || saveFlags) BuildMI(MBB,MI,dl,TII->get(X86::POPF32)); // POPF32
  // insert a store instruction so that it uses %dead as the base reg
  const MachineInstrBuilder& MIB = BuildMI(MBB,MI,dl,MI->getDesc());
  for(unsigned i = 0; i < memIndex; ++i)
	MIB.addOperand(MI->getOperand(i));  
  MIB.addReg(dead).addImm(1).addReg(0).addImm(0).addReg(0);
  for(unsigned i = memIndex+5, end = MI->getNumOperands(); i < end; ++i)
	MIB.addOperand(MI->getOperand(i));
  if(saved) BuildMI(MBB,MI,dl,TII->get(X86::POP32r),dead); // popl %dead
  MI->eraseFromParent();
}

void X86SFIOptPass::insertMaskBeforeJMP32m(MachineBasicBlock& MBB, MachineInstr* MI,
										   DebugLoc& dl, const TargetInstrInfo* TII,
										   const unsigned memIndex){
  const TargetRegisterInfo* TRI = MI->getParent()->getParent()->getTarget().getRegisterInfo();
  if(onStack(MI, memIndex)) return;
  if(!X86Inst::indirectLoadStore(*MI, memIndex)) return; // no need to sandbox direct memory location
  if(baseReg2Mem(MI, memIndex)) { // if MI is in this form: movl %eax, (%ebx), sandbox %ebx
	unsigned base = MI->getOperand(memIndex).getReg();
	// andl &DATA_MASK, %base
	BuildMI(MBB,MI,dl,TII->get(X86::AND32ri),base).addReg(base).addImm(DATA_MASK);
	++numAnds; return;
  }
  unsigned dead = 0;
  /*if(useDeadRegs)*/ dead = findDeadReg(MI, memIndex);
  // TODO MI can change %dead
  if(dead == 0)	{
	MI->getParent()->getParent()->dump();
	abort();
	BitVector kills = MI->getKills();
	MI->dump();
	llvm::errs() << "kills: \n";
	for(unsigned i = 0, e = TRI->getNumRegs(); i != e; ++i)
	  if(kills[i])
		llvm::errs() << TRI->get(i).Name << " ";
	llvm::errs() << "\n";
	MI->getParent()->getParent()->dump();
	abort();
  }
  // leal mem_loc, %dead
  const MachineInstrBuilder& LEA =
	BuildMI(MBB,MI,dl,TII->get(X86::LEA32r),dead)
	.addOperand(MI->getOperand(memIndex+0))
	.addOperand(MI->getOperand(memIndex+1))
	.addOperand(MI->getOperand(memIndex+2))
	.addOperand(MI->getOperand(memIndex+3)); 
  for(MachineInstr::mmo_iterator MMI = MI->memoperands_begin(),
		MME = MI->memoperands_end(); MMI != MME; ++MMI)
	LEA.addMemOperand(*MMI);
  //andl &DATA_MASK, %dead
  BuildMI(MBB,MI,dl,TII->get(X86::AND32ri),dead).addReg(dead).addImm(DATA_MASK); 
  ++numAnds;
  // insert a jmp32m so that it uses %dead as the base reg
  BuildMI(MBB,MI,dl,MI->getDesc()).addReg(dead).addImm(1).addReg(0).addImm(0).addReg(0);
  MI->eraseFromParent();
}

unsigned X86SFIOptPass::getMemIndex(const MachineInstr* const MI){
  return X86Inst::getMemIndex(*MI);
}

void X86SFIOptPass::insertMaskBeforeREP_MOVSX(MachineBasicBlock& MBB, MachineInstr* MI,
											  DebugLoc& dl, const TargetInstrInfo* TII) {
  const TargetRegisterInfo* TRI = MI->getParent()->getParent()->getTarget().getRegisterInfo();
  const bool saveFlags = needsPushf(MI,TRI);
  if(allPushf || saveFlags) {++numPushf; BuildMI(MBB,MI,dl,TII->get(X86::PUSHF32));}
  // andl &DATA_MASK, %esi
  BuildMI(MBB,MI,dl,TII->get(X86::AND32ri),X86::ESI).addReg(X86::ESI).addImm(DATA_MASK);
  // andl &DATA_MASK, %edi
  BuildMI(MBB,MI,dl,TII->get(X86::AND32ri),X86::EDI).addReg(X86::EDI).addImm(DATA_MASK);
  numAnds += 2;
  if(allPushf || saveFlags) BuildMI(MBB,MI,dl,TII->get(X86::POPF32)); // POPF32
}

void X86SFIOptPass::insertMaskBeforeCALL32m(MachineBasicBlock& MBB, MachineInstr* MI,
											DebugLoc& dl, const TargetInstrInfo* TII,
											const unsigned memIndex){
  // use %eax to sandbox MI
  const unsigned dead = X86::EAX;
  // leal mem_loc, %dead
  const MachineInstrBuilder& LEA =
	BuildMI(MBB,MI,dl,TII->get(X86::LEA32r),dead)
	.addOperand(MI->getOperand(memIndex+0))
	.addOperand(MI->getOperand(memIndex+1))
	.addOperand(MI->getOperand(memIndex+2))
	.addOperand(MI->getOperand(memIndex+3));
  for(MachineInstr::mmo_iterator MMI = MI->memoperands_begin(),
		MME = MI->memoperands_end(); MMI != MME; ++MMI)
	LEA.addMemOperand(*MMI);
  // andl &DATA_MASK, %dead
  BuildMI(MBB, MI, dl, TII->get(X86::AND32ri),dead).addReg(dead).addImm(DATA_MASK);
  ++numAnds;
  // CALL32r (%dead)
  BuildMI(MBB,MI,dl,MI->getDesc()).addReg(dead).addImm(1).addReg(0).addImm(0).addReg(0);
  MI->eraseFromParent();
}

void X86SFIOptPass::insertMaskBeforeTAILJMPm(MachineBasicBlock& MBB, MachineInstr* MI,
											 DebugLoc& dl, const TargetInstrInfo* TII,
											 const unsigned memIndex){
  insertMaskBeforeCALL32m(MBB,MI,dl,TII,memIndex);
}

// inserts mask instructions to ensure that the code does not
// write outside the data region. We only mask store instructions
// load can be masked too but it incurs too much overhead
bool X86SFIOptPass::runOnMachineFunction(MachineFunction& F){
  //llvm::errs() << "X86SFIOptPass::runOnMachineFunction(" << F.getFunction()->getName() << ")\n";
  if(F.getFunction()->getName() == "FunGaloisCyc"){
	llvm::errs() << "before X86SFIOptPass\n";
	F.getBlockNumbered(49)->dump();
  }

  TII = F.getTarget().getInstrInfo();
  TRI = F.getTarget().getRegisterInfo();
  //MFI = F.getFrameInfo();
  //RegInfo = &F.getRegInfo();
  //AllocatableSet = TRI->getAllocatableSet(F);

  // get our loop information 
  //MLI = &getAnalysis<MachineLoopInfo>();
  //DT  = &getAnalysis<MachineDominatorTree>();
  //AA  = &getAnalysis<AliasAnalysis>();
  
  DebugLoc dl; //// FIXME, this is nowhere
  
  for(MachineFunction::iterator FI = F.begin(); FI != F.end(); ++FI){
	MachineBasicBlock& MBB = *FI;
	for(MachineBasicBlock::iterator I = MBB.begin(); I != MBB.end();){
	  MachineInstr* MI = I++;
	  const TargetInstrDesc& TID = MI->getDesc();
	  // if MI stores to data section, sandbox it
	  // we sandbox only those store instructions on which onStack returns false
	  // we also sandbox instructions that modify %esp or %ebp
	  // if the instruction stores to memory and changes %esp or %ebp
	  // we need to sandbox the store and %esp or %ebp. There are not
	  // many such instructions since few instructions store and change %esp
	  // or %ebp at the same time
	  if(TID.mayStore() && !TID.mayLoad()) { // store only
		// these instructions only store, they do not load
		switch(MI->getOpcode()){
		case X86::EXTRACTPSmr:
		case X86::FNSTCW16m:
		case X86::FP32_TO_INT16_IN_MEM:
		case X86::FP32_TO_INT32_IN_MEM:
		case X86::FP32_TO_INT64_IN_MEM:
		case X86::FP64_TO_INT16_IN_MEM:
		case X86::FP64_TO_INT32_IN_MEM:
		case X86::FP64_TO_INT64_IN_MEM:
		case X86::FP80_TO_INT16_IN_MEM:
		case X86::FP80_TO_INT32_IN_MEM:
		case X86::FP80_TO_INT64_IN_MEM:
		case X86::ISTT_FP16m:
		case X86::ISTT_FP32m:
		case X86::ISTT_FP64m:
		case X86::ISTT_Fp16m32:
		case X86::ISTT_Fp16m64:
		case X86::ISTT_Fp16m80:
		case X86::ISTT_Fp32m32:
		case X86::ISTT_Fp32m64:
		case X86::ISTT_Fp32m80:
		case X86::ISTT_Fp64m32:
		case X86::ISTT_Fp64m64:
		case X86::ISTT_Fp64m80:
		case X86::IST_F16m:
		case X86::IST_F32m:
		case X86::IST_FP16m:
		case X86::IST_FP32m:
		case X86::IST_FP64m:
		case X86::IST_Fp16m32:
		case X86::IST_Fp16m64:
		case X86::IST_Fp16m80:
		case X86::IST_Fp32m32:
		case X86::IST_Fp32m64:
		case X86::IST_Fp32m80:
		  insertMaskBeforeStore(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP,TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::IST_Fp64m32:
		case X86::IST_Fp64m64:
		case X86::IST_Fp64m80:
		case X86::MMX_MOVD64mr:
		case X86::MMX_MOVQ64mr:
		  abort();
		case X86::MOV16mi:
		case X86::MOV16mr:
		case X86::MOV32mi:
		case X86::MOV32mr:
		  insertMaskBeforeStore(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP,TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::MOV32mr_TC:
		  insertMaskBeforeStore(MBB,MI,dl,TII,0);
		  if(MI->modifiesRegister(X86::ESP,TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::MOV64mi32:
		case X86::MOV64mr:
		case X86::MOV64mr_TC:
		  abort();
		case X86::MOV8mi:
		case X86::MOV8mr:
		case X86::MOV8mr_NOREX:
		case X86::MOVAPDmr:
		case X86::MOVAPSmr:
		case X86::MOVDQAmr:
		case X86::MOVDQUmr:
		case X86::MOVHPDmr:
		case X86::MOVHPSmr:
		case X86::MOVLPDmr:
		case X86::MOVLPSmr:
		case X86::MOVNTDQ_64mr:
		case X86::MOVNTDQmr:
		case X86::MOVNTI_64mr:
		case X86::MOVNTImr:
		case X86::MOVNTPDmr:
		case X86::MOVNTPSmr:
		case X86::MOVPDI2DImr:
		case X86::MOVPQI2QImr:
		case X86::MOVSDmr:
		case X86::MOVSDto64mr:
		case X86::MOVSS2DImr:
		case X86::MOVSSmr:
		case X86::MOVUPDmr:
		case X86::MOVUPSmr:
		case X86::PEXTRDmr:
		case X86::PEXTRQmr:
		  insertMaskBeforeStore(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP,TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::PUSH16r:
		  break;
		case X86::PUSH16rmm:
		  insertMaskBeforeStore(MBB,MI,dl,TII,getMemIndex(MI));
		  break;
		case X86::PUSH16rmr:
		case X86::PUSH32r:
		  break;
		case X86::PUSH32rmm:
		  insertMaskBeforeStore(MBB,MI,dl,TII,getMemIndex(MI));
		  break;
		case X86::PUSH32rmr:
		  break;
		case X86::PUSH64i16:
		case X86::PUSH64i32:
		case X86::PUSH64i8:
		case X86::PUSH64r:
		case X86::PUSH64rmm:
		case X86::PUSH64rmr:
		  abort();
		case X86::PUSHA32:
		case X86::PUSHF16:
		case X86::PUSHF32:
		  break;
		case X86::PUSHF64:
		  abort();
		case X86::PUSHi16:
		case X86::PUSHi32:
		case X86::PUSHi8:
		  break;
		case X86::REP_STOSB:
		case X86::REP_STOSD:
		case X86::REP_STOSQ:
		case X86::REP_STOSW:
		  MI->dump(); abort();
		case X86::SETAEm:
		case X86::SETAm:
		case X86::SETBEm:
		case X86::SETBm:
		case X86::SETEm:
		case X86::SETGEm:
		case X86::SETGm:
		case X86::SETLEm:
		case X86::SETLm:
		case X86::SETNEm:
		case X86::SETNOm:
		case X86::SETNPm:
		case X86::SETNSm:
		case X86::SETOm:
		case X86::SETPm:
		case X86::SETSm:
		case X86::ST_F32m:
		case X86::ST_F64m:
		case X86::ST_FP32m:
		case X86::ST_FP64m:
		case X86::ST_FP80m:
		case X86::ST_Fp32m:
		case X86::ST_Fp64m:
		case X86::ST_Fp64m32:
		case X86::ST_Fp80m32:
		case X86::ST_Fp80m64:
		case X86::ST_FpP32m:
		case X86::ST_FpP64m:
		case X86::ST_FpP64m32:
		case X86::ST_FpP80m:
		case X86::ST_FpP80m32:
		case X86::ST_FpP80m64:
		case X86::VEXTRACTPSmr:
		case X86::VMOVAPDmr:
		case X86::VMOVAPSmr:
		case X86::VMOVDQAmr:
		case X86::VMOVDQUmr:
		case X86::VMOVHPDmr:
		case X86::VMOVHPSmr:
		case X86::VMOVLPDmr:
		case X86::VMOVLPSmr:
		case X86::VMOVNTDQ_64mr:
		case X86::VMOVNTDQmr:
		case X86::VMOVNTPDmr:
		case X86::VMOVNTPSmr:
		case X86::VMOVPDI2DImr:
		case X86::VMOVPQI2QImr:
		case X86::VMOVSDmr:
		case X86::VMOVSS2DImr:
		case X86::VMOVSSmr:
		case X86::VMOVUPDmr:
		case X86::VMOVUPSmr:
		case X86::VPEXTRDmr:
		case X86::VPEXTRQmr:
		  insertMaskBeforeStore(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		default:
		  llvm::errs() << "inst unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort();
		}
	  } else if(sandboxLoads && TID.mayLoad() && !TID.mayStore()) { //  load only
		// these instructions only load. they do not store
		switch(MI->getOpcode()){
		case X86::ADC16rm:
		case X86::ADC32rm:
		case X86::ADC64rm:
		case X86::ADC8rm:
		case X86::ADD16rm:
		case X86::ADD32rm:
		case X86::ADD64rm:
		case X86::ADD8rm:
		case X86::ADDPDrm:
		case X86::ADDPSrm:
		case X86::ADDSDrm:
		case X86::ADDSDrm_Int:
		case X86::ADDSSrm:
		case X86::ADDSSrm_Int:
		case X86::ADDSUBPDrm:
		case X86::ADDSUBPSrm:
		case X86::ADD_F32m:
		case X86::ADD_F64m:
		case X86::ADD_FI16m:
		case X86::ADD_FI32m:
		case X86::ADD_Fp32m:
		case X86::ADD_Fp64m:
		case X86::ADD_Fp64m32:
		case X86::ADD_Fp80m32:
		case X86::ADD_Fp80m64:
		case X86::ADD_FpI16m32:
		case X86::ADD_FpI16m64:
		case X86::ADD_FpI16m80:
		case X86::ADD_FpI32m32:
		case X86::ADD_FpI32m64:
		case X86::ADD_FpI32m80:
		case X86::AESDECLASTrm:
		case X86::AESDECrm:
		case X86::AESENCLASTrm:
		case X86::AESENCrm:
		case X86::AESIMCrm:
		case X86::AESKEYGENASSIST128rm:
		case X86::AND16rm:
		case X86::AND32rm:
		case X86::AND64rm:
		case X86::AND8rm:
		case X86::ANDNPDrm:
		case X86::ANDNPSrm:
		case X86::ANDPDrm:
		case X86::ANDPSrm:
		case X86::BLENDPDrmi:
		case X86::BLENDPSrmi:
		case X86::BLENDVPDrm0:
		case X86::BLENDVPSrm0:
		case X86::BSF16rm:
		case X86::BSF32rm:
		case X86::BSF64rm:
		case X86::BSR16rm:
		case X86::BSR32rm:
		case X86::BSR64rm:
		case X86::BT16mi8:
		case X86::BT32mi8:
		case X86::BT64mi8:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;			
		case X86::CALL32m:
		  insertMaskBeforeCALL32m(MBB,MI,dl,TII,0);
		  break;
		case X86::CALL64m:
		  abort();
		case X86::CMOVA16rm:
		case X86::CMOVA32rm:
		case X86::CMOVA64rm:
		case X86::CMOVAE16rm:
		case X86::CMOVAE32rm:
		case X86::CMOVAE64rm:
		case X86::CMOVB16rm:
		case X86::CMOVB32rm:
		case X86::CMOVB64rm:
		case X86::CMOVBE16rm:
		case X86::CMOVBE32rm:
		case X86::CMOVBE64rm:
		case X86::CMOVE16rm:
		case X86::CMOVE32rm:
		case X86::CMOVE64rm:
		case X86::CMOVG16rm:
		case X86::CMOVG32rm:
		case X86::CMOVG64rm:
		case X86::CMOVGE16rm:
		case X86::CMOVGE32rm:
		case X86::CMOVGE64rm:
		case X86::CMOVL16rm:
		case X86::CMOVL32rm:
		case X86::CMOVL64rm:
		case X86::CMOVLE16rm:
		case X86::CMOVLE32rm:
		case X86::CMOVLE64rm:
		case X86::CMOVNE16rm:
		case X86::CMOVNE32rm:
		case X86::CMOVNE64rm:
		case X86::CMOVNO16rm:
		case X86::CMOVNO32rm:
		case X86::CMOVNO64rm:
		case X86::CMOVNP16rm:
		case X86::CMOVNP32rm:
		case X86::CMOVNP64rm:
		case X86::CMOVNS16rm:
		case X86::CMOVNS32rm:
		case X86::CMOVNS64rm:
		case X86::CMOVO16rm:
		case X86::CMOVO32rm:
		case X86::CMOVO64rm:
		case X86::CMOVP16rm:
		case X86::CMOVP32rm:
		case X86::CMOVP64rm:
		case X86::CMOVS16rm:
		case X86::CMOVS32rm:
		case X86::CMOVS64rm:
		case X86::CMP16mi:
		case X86::CMP16mi8:
		case X86::CMP16mr:
		case X86::CMP16rm:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::CMP32mi:
		  if(isCFICMP(*MI))
			insertMaskBeforeCheck(MBB,MI,dl,TII,getMemIndex(MI));
		  else {
			insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  }
		  break;
		case X86::CMP32mi8:
		case X86::CMP32mr:
		case X86::CMP32rm:
		case X86::CMP64mi32:
		case X86::CMP64mi8:
		case X86::CMP64mr:
		case X86::CMP64rm:
		case X86::CMP8mi:
		case X86::CMP8mr:
		case X86::CMP8rm:
		case X86::CMPPDrmi:
		case X86::CMPPSrmi:
		case X86::CMPSDrm:
		case X86::CMPSDrm_alt:
		case X86::CMPSSrm:
		case X86::CMPSSrm_alt:
		case X86::CRC32m16:
		case X86::CRC32m32:
		case X86::CRC32m8:
		case X86::CRC64m64:
		case X86::CRC64m8:
		case X86::CVTSD2SSrm:
		case X86::CVTSI2SD64rm:
		case X86::CVTSI2SDrm:
		case X86::CVTSI2SS64rm:
		case X86::CVTSI2SSrm:
		case X86::CVTSS2SDrm:
		case X86::CVTTSD2SI64rm:
		case X86::CVTTSD2SIrm:
		case X86::CVTTSS2SI64rm:
		case X86::CVTTSS2SIrm:
		case X86::DIV16m:
		case X86::DIV32m:
		case X86::DIV64m:
		case X86::DIV8m:
		case X86::DIVPDrm:
		case X86::DIVPSrm:
		case X86::DIVR_F32m:
		case X86::DIVR_F64m:
		case X86::DIVR_FI16m:
		case X86::DIVR_FI32m:
		case X86::DIVR_Fp32m:
		case X86::DIVR_Fp64m:
		case X86::DIVR_Fp64m32:
		case X86::DIVR_Fp80m32:
		case X86::DIVR_Fp80m64:
		case X86::DIVR_FpI16m32:
		case X86::DIVR_FpI16m64:
		case X86::DIVR_FpI16m80:
		case X86::DIVR_FpI32m32:
		case X86::DIVR_FpI32m64:
		case X86::DIVR_FpI32m80:
		case X86::DIVSDrm:
		case X86::DIVSDrm_Int:
		case X86::DIVSSrm:
		case X86::DIVSSrm_Int:
		case X86::DIV_F32m:
		case X86::DIV_F64m:
		case X86::DIV_FI16m:
		case X86::DIV_FI32m:
		case X86::DIV_Fp32m:
		case X86::DIV_Fp64m:
		case X86::DIV_Fp64m32:
		case X86::DIV_Fp80m32:
		case X86::DIV_Fp80m64:
		case X86::DIV_FpI16m32:
		case X86::DIV_FpI16m64:
		case X86::DIV_FpI16m80:
		case X86::DIV_FpI32m32:
		case X86::DIV_FpI32m64:
		case X86::DIV_FpI32m80:
		case X86::DPPDrmi:
		case X86::DPPSrmi:
		case X86::FLDCW16m:
		case X86::FS_MOV32rm:
		case X86::FsANDNPDrm:
		case X86::FsANDNPSrm:
		case X86::FsANDPDrm:
		case X86::FsANDPSrm:
		case X86::FsMOVAPDrm:
		case X86::FsMOVAPSrm:
		case X86::FsORPDrm:
		case X86::FsORPSrm:
		case X86::FsXORPDrm:
		case X86::FsXORPSrm:
		case X86::GS_MOV32rm:
		case X86::HADDPDrm:
		case X86::HADDPSrm:
		case X86::HSUBPDrm:
		case X86::HSUBPSrm:
		case X86::IDIV16m:
		case X86::IDIV32m:
		case X86::IDIV64m:
		case X86::IDIV8m:
		case X86::ILD_F16m:
		case X86::ILD_F32m:
		case X86::ILD_F64m:
		case X86::ILD_Fp16m32:
		case X86::ILD_Fp16m64:
		case X86::ILD_Fp16m80:
		case X86::ILD_Fp32m32:
		case X86::ILD_Fp32m64:
		case X86::ILD_Fp32m80:
		case X86::ILD_Fp64m32:
		case X86::ILD_Fp64m64:
		case X86::ILD_Fp64m80:
		case X86::IMUL16m:
		case X86::IMUL16rm:
		case X86::IMUL16rmi:
		case X86::IMUL16rmi8:
		case X86::IMUL32m:
		case X86::IMUL32rm:
		case X86::IMUL32rmi:
		case X86::IMUL32rmi8:
		case X86::IMUL64m:
		case X86::IMUL64rm:
		case X86::IMUL64rmi32:
		case X86::IMUL64rmi8:
		case X86::IMUL8m:
		case X86::INSERTPSrm:
		case X86::Int_CMPSDrm:
		case X86::Int_CMPSSrm:
		case X86::Int_COMISDrm:
		case X86::Int_COMISSrm:
		case X86::Int_CVTDQ2PDrm:
		case X86::Int_CVTDQ2PSrm:
		case X86::Int_CVTPD2DQrm:
		case X86::Int_CVTPD2PIrm:
		case X86::Int_CVTPD2PSrm:
		case X86::Int_CVTPI2PDrm:
		case X86::Int_CVTPI2PSrm:
		case X86::Int_CVTPS2DQrm:
		case X86::Int_CVTPS2PDrm:
		case X86::Int_CVTPS2PIrm:
		case X86::Int_CVTSD2SI64rm:
		case X86::Int_CVTSD2SIrm:
		case X86::Int_CVTSD2SSrm:
		case X86::Int_CVTSI2SD64rm:
		case X86::Int_CVTSI2SDrm:
		case X86::Int_CVTSI2SS64rm:
		case X86::Int_CVTSI2SSrm:
		case X86::Int_CVTSS2SDrm:
		case X86::Int_CVTSS2SI64rm:
		case X86::Int_CVTSS2SIrm:
		case X86::Int_CVTTPD2DQrm:
		case X86::Int_CVTTPD2PIrm:
		case X86::Int_CVTTPS2DQrm:
		case X86::Int_CVTTPS2PIrm:
		case X86::Int_CVTTSD2SI64rm:
		case X86::Int_CVTTSD2SIrm:
		case X86::Int_CVTTSS2SI64rm:
		case X86::Int_CVTTSS2SIrm:
		case X86::Int_UCOMISDrm:
		case X86::Int_UCOMISSrm:
		case X86::Int_VCMPSDrm:
		case X86::Int_VCMPSSrm:
		case X86::Int_VCOMISDrm:
		case X86::Int_VCOMISSrm:
		case X86::Int_VCVTDQ2PDrm:
		case X86::Int_VCVTDQ2PSrm:
		case X86::Int_VCVTPD2DQrm:
		case X86::Int_VCVTPD2PSrm:
		case X86::Int_VCVTPS2DQrm:
		case X86::Int_VCVTPS2PDrm:
		case X86::Int_VCVTSD2SIrm:
		case X86::Int_VCVTSD2SSrm:
		case X86::Int_VCVTSS2SDrm:
		case X86::Int_VCVTSS2SIrm:
		case X86::Int_VCVTTPD2DQrm:
		case X86::Int_VCVTTPS2DQrm:
		case X86::Int_VUCOMISDrm:
		case X86::Int_VUCOMISSrm:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::JMP32m:
		  insertMaskBeforeJMP32m(MBB,MI,dl,TII,0);
		  break;
		case X86::JMP64m:
		  abort();
		case X86::LDDQUrm:
		case X86::LD_F32m:
		case X86::LD_F64m:
		case X86::LD_F80m:
		case X86::LD_Fp32m:
		case X86::LD_Fp32m64:
		case X86::LD_Fp32m80:
		case X86::LD_Fp64m:
		case X86::LD_Fp64m80:
		case X86::LD_Fp80m:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::LEAVE:
		  break;
		case X86::LEAVE64:
		  abort();
		case X86::MAXPDrm:
		case X86::MAXPDrm_Int:
		case X86::MAXPSrm:
		case X86::MAXPSrm_Int:
		case X86::MAXSDrm:
		case X86::MAXSDrm_Int:
		case X86::MAXSSrm:
		case X86::MAXSSrm_Int:
		case X86::MINPDrm:
		case X86::MINPDrm_Int:
		case X86::MINPSrm:
		case X86::MINPSrm_Int:
		case X86::MINSDrm:
		case X86::MINSDrm_Int:
		case X86::MINSSrm:
		case X86::MINSSrm_Int:
		case X86::MMX_CVTPD2PIrm:
		case X86::MMX_CVTPI2PDrm:
		case X86::MMX_CVTPI2PSrm:
		case X86::MMX_CVTPS2PIrm:
		case X86::MMX_CVTTPD2PIrm:
		case X86::MMX_CVTTPS2PIrm:
		case X86::MMX_MOVD64rm:
		case X86::MMX_MOVQ64rm:
		case X86::MMX_MOVZDI2PDIrm:
		case X86::MMX_PACKSSDWrm:
		case X86::MMX_PACKSSWBrm:
		case X86::MMX_PACKUSWBrm:
		case X86::MMX_PADDBrm:
		case X86::MMX_PADDDrm:
		case X86::MMX_PADDQrm:
		case X86::MMX_PADDSBrm:
		case X86::MMX_PADDSWrm:
		case X86::MMX_PADDUSBrm:
		case X86::MMX_PADDUSWrm:
		case X86::MMX_PADDWrm:
		case X86::MMX_PANDNrm:
		case X86::MMX_PANDrm:
		case X86::MMX_PAVGBrm:
		case X86::MMX_PAVGWrm:
		case X86::MMX_PCMPEQBrm:
		case X86::MMX_PCMPEQDrm:
		case X86::MMX_PCMPEQWrm:
		case X86::MMX_PCMPGTBrm:
		case X86::MMX_PCMPGTDrm:
		case X86::MMX_PCMPGTWrm:
		case X86::MMX_PINSRWrmi:
		case X86::MMX_PMADDWDrm:
		case X86::MMX_PMAXSWrm:
		case X86::MMX_PMAXUBrm:
		case X86::MMX_PMINSWrm:
		case X86::MMX_PMINUBrm:
		case X86::MMX_PMULHUWrm:
		case X86::MMX_PMULHWrm:
		case X86::MMX_PMULLWrm:
		case X86::MMX_PMULUDQrm:
		case X86::MMX_PORrm:
		case X86::MMX_PSADBWrm:
		case X86::MMX_PSHUFWmi:
		case X86::MMX_PSLLDrm:
		case X86::MMX_PSLLQrm:
		case X86::MMX_PSLLWrm:
		case X86::MMX_PSRADrm:
		case X86::MMX_PSRAWrm:
		case X86::MMX_PSRLDrm:
		case X86::MMX_PSRLQrm:
		case X86::MMX_PSRLWrm:
		case X86::MMX_PSUBBrm:
		case X86::MMX_PSUBDrm:
		case X86::MMX_PSUBQrm:
		case X86::MMX_PSUBSBrm:
		case X86::MMX_PSUBSWrm:
		case X86::MMX_PSUBUSBrm:
		case X86::MMX_PSUBUSWrm:
		case X86::MMX_PSUBWrm:
		case X86::MMX_PUNPCKHBWrm:
		case X86::MMX_PUNPCKHDQrm:
		case X86::MMX_PUNPCKHWDrm:
		case X86::MMX_PUNPCKLBWrm:
		case X86::MMX_PUNPCKLDQrm:
		case X86::MMX_PUNPCKLWDrm:
		case X86::MMX_PXORrm:
		case X86::MOV16rm:
		case X86::MOV32rm:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::MOV32rm_TC:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,1);
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::MOV64FSrm:
		case X86::MOV64GSrm:
		case X86::MOV64rm:
		case X86::MOV64rm_TC:
		case X86::MOV64toSDrm:
		case X86::MOV8rm:
		case X86::MOV8rm_NOREX:
		case X86::MOVAPDrm:
		case X86::MOVAPSrm:
		case X86::MOVDDUPrm:
		case X86::MOVDI2PDIrm:
		case X86::MOVDI2SSrm:
		case X86::MOVDQArm:
		case X86::MOVDQUrm:
		case X86::MOVDQUrm_Int:
		case X86::MOVHPDrm:
		case X86::MOVHPSrm:
		case X86::MOVLPDrm:
		case X86::MOVLPSrm:
		case X86::MOVNTDQArm:
		case X86::MOVQI2PQIrm:
		case X86::MOVSDrm:
		case X86::MOVSHDUPrm:
		case X86::MOVSLDUPrm:
		case X86::MOVSSrm:
		case X86::MOVSX16rm8:
		case X86::MOVSX32rm16:
		case X86::MOVSX32rm8:
		case X86::MOVSX64rm16:
		case X86::MOVSX64rm32:
		case X86::MOVSX64rm8:
		case X86::MOVUPDrm:
		case X86::MOVUPDrm_Int:
		case X86::MOVUPSrm:
		case X86::MOVUPSrm_Int:
		case X86::MOVZDI2PDIrm:
		case X86::MOVZPQILo2PQIrm:
		case X86::MOVZQI2PQIrm:
		case X86::MOVZX16rm8:
		case X86::MOVZX32_NOREXrm8:
		case X86::MOVZX32rm16:
		case X86::MOVZX32rm8:
		case X86::MOVZX64rm16:
		case X86::MOVZX64rm32:
		case X86::MOVZX64rm8:
		case X86::MPSADBWrmi:
		case X86::MUL16m:
		case X86::MUL32m:
		case X86::MUL64m:
		case X86::MUL8m:
		case X86::MULPDrm:
		case X86::MULPSrm:
		case X86::MULSDrm:
		case X86::MULSDrm_Int:
		case X86::MULSSrm:
		case X86::MULSSrm_Int:
		case X86::MUL_F32m:
		case X86::MUL_F64m:
		case X86::MUL_FI16m:
		case X86::MUL_FI32m:
		case X86::MUL_Fp32m:
		case X86::MUL_Fp64m:
		case X86::MUL_Fp64m32:
		case X86::MUL_Fp80m32:
		case X86::MUL_Fp80m64:
		case X86::MUL_FpI16m32:
		case X86::MUL_FpI16m64:
		case X86::MUL_FpI16m80:
		case X86::MUL_FpI32m32:
		case X86::MUL_FpI32m64:
		case X86::MUL_FpI32m80:
		case X86::OR16rm:
		case X86::OR32rm:
		case X86::OR64rm:
		case X86::OR8rm:
		case X86::ORPDrm:
		case X86::ORPSrm:
		case X86::PABSBrm128:
		case X86::PABSBrm64:
		case X86::PABSDrm128:
		case X86::PABSDrm64:
		case X86::PABSWrm128:
		case X86::PABSWrm64:
		case X86::PACKSSDWrm:
		case X86::PACKSSWBrm:
		case X86::PACKUSDWrm:
		case X86::PACKUSWBrm:
		case X86::PADDBrm:
		case X86::PADDDrm:
		case X86::PADDQrm:
		case X86::PADDSBrm:
		case X86::PADDSWrm:
		case X86::PADDUSBrm:
		case X86::PADDUSWrm:
		case X86::PADDWrm:
		case X86::PANDNrm:
		case X86::PANDrm:
		case X86::PAVGBrm:
		case X86::PAVGWrm:
		case X86::PBLENDVBrm0:
		case X86::PBLENDWrmi:
		case X86::PCMPEQBrm:
		case X86::PCMPEQDrm:
		case X86::PCMPEQQrm:
		case X86::PCMPEQWrm:
		case X86::PCMPESTRIArm:
		case X86::PCMPESTRICrm:
		case X86::PCMPESTRIOrm:
		case X86::PCMPESTRISrm:
		case X86::PCMPESTRIZrm:
		case X86::PCMPESTRIrm:
		case X86::PCMPESTRM128MEM:
		case X86::PCMPGTBrm:
		case X86::PCMPGTDrm:
		case X86::PCMPGTQrm:
		case X86::PCMPGTWrm:
		case X86::PCMPISTRIArm:
		case X86::PCMPISTRICrm:
		case X86::PCMPISTRIOrm:
		case X86::PCMPISTRISrm:
		case X86::PCMPISTRIZrm:
		case X86::PCMPISTRIrm:
		case X86::PCMPISTRM128MEM:
		case X86::PHADDDrm128:
		case X86::PHADDDrm64:
		case X86::PHADDSWrm128:
		case X86::PHADDSWrm64:
		case X86::PHADDWrm128:
		case X86::PHADDWrm64:
		case X86::PHMINPOSUWrm128:
		case X86::PHSUBDrm128:
		case X86::PHSUBDrm64:
		case X86::PHSUBSWrm128:
		case X86::PHSUBSWrm64:
		case X86::PHSUBWrm128:
		case X86::PHSUBWrm64:
		case X86::PINSRBrm:
		case X86::PINSRDrm:
		case X86::PINSRQrm:
		case X86::PINSRWrmi:
		case X86::PMADDUBSWrm128:
		case X86::PMADDUBSWrm64:
		case X86::PMADDWDrm:
		case X86::PMAXSBrm:
		case X86::PMAXSDrm:
		case X86::PMAXSWrm:
		case X86::PMAXUBrm:
		case X86::PMAXUDrm:
		case X86::PMAXUWrm:
		case X86::PMINSBrm:
		case X86::PMINSDrm:
		case X86::PMINSWrm:
		case X86::PMINUBrm:
		case X86::PMINUDrm:
		case X86::PMINUWrm:
		case X86::PMOVSXBDrm:
		case X86::PMOVSXBQrm:
		case X86::PMOVSXBWrm:
		case X86::PMOVSXDQrm:
		case X86::PMOVSXWDrm:
		case X86::PMOVSXWQrm:
		case X86::PMOVZXBDrm:
		case X86::PMOVZXBQrm:
		case X86::PMOVZXBWrm:
		case X86::PMOVZXDQrm:
		case X86::PMOVZXWDrm:
		case X86::PMOVZXWQrm:
		case X86::PMULDQrm:
		case X86::PMULHRSWrm128:
		case X86::PMULHRSWrm64:
		case X86::PMULHUWrm:
		case X86::PMULHWrm:
		case X86::PMULLDrm:
		case X86::PMULLWrm:
		case X86::PMULUDQrm:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::POP16r:
		  if(MI->getOperand(0).getReg() == X86::SP)
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  else if(MI->getOperand(0).getReg() == X86::BP)
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::POP16rmm:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  break;
		case X86::POP16rmr:
		  if(MI->getOperand(0).getReg() == X86::SP)
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  else if(MI->getOperand(0).getReg() == X86::BP)
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::POP32r:
		  if(MI->getOperand(0).getReg() == X86::ESP)
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  else if(MI->getOperand(0).getReg() == X86::EBP)
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::POP32rmm:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  break;
		case X86::POP32rmr:
		  if(MI->getOperand(0).getReg() == X86::ESP)
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  else if(MI->getOperand(0).getReg() == X86::EBP)
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::POP64r:
		case X86::POP64rmm:
		case X86::POP64rmr:
		  abort();
		case X86::POPA32:
		  insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::POPCNT16rm:
		case X86::POPCNT32rm:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::POPCNT64rm:
		  abort();
		case X86::POPF16:
		case X86::POPF32:
		  break;
		case X86::POPF64:
		  abort(); // no need to sandbox pop
		case X86::PORrm:
		case X86::PSADBWrm:
		case X86::PSHUFBrm128:
		case X86::PSHUFBrm64:
		case X86::PSHUFDmi:
		case X86::PSHUFHWmi:
		case X86::PSHUFLWmi:
		case X86::PSIGNBrm128:
		case X86::PSIGNBrm64:
		case X86::PSIGNDrm128:
		case X86::PSIGNDrm64:
		case X86::PSIGNWrm128:
		case X86::PSIGNWrm64:
		case X86::PSLLDrm:
		case X86::PSLLQrm:
		case X86::PSLLWrm:
		case X86::PSRADrm:
		case X86::PSRAWrm:
		case X86::PSRLDrm:
		case X86::PSRLQrm:
		case X86::PSRLWrm:
		case X86::PSUBBrm:
		case X86::PSUBDrm:
		case X86::PSUBQrm:
		case X86::PSUBSBrm:
		case X86::PSUBSWrm:
		case X86::PSUBUSBrm:
		case X86::PSUBUSWrm:
		case X86::PSUBWrm:
		case X86::PTESTrm:
		case X86::PUNPCKHBWrm:
		case X86::PUNPCKHDQrm:
		case X86::PUNPCKHQDQrm:
		case X86::PUNPCKHWDrm:
		case X86::PUNPCKLBWrm:
		case X86::PUNPCKLDQrm:
		case X86::PUNPCKLQDQrm:
		case X86::PUNPCKLWDrm:
		case X86::PXORrm:
		case X86::RCPPSm:
		case X86::RCPPSm_Int:
		case X86::RCPSSm:
		case X86::RCPSSm_Int:
		case X86::ROUNDPDm_Int:
		case X86::ROUNDPSm_Int:
		case X86::ROUNDSDm_Int:
		case X86::ROUNDSSm_Int:
		case X86::RSQRTPSm:
		case X86::RSQRTPSm_Int:
		case X86::RSQRTSSm:
		case X86::RSQRTSSm_Int:
		case X86::SBB16rm:
		case X86::SBB32rm:
		case X86::SBB64rm:
		case X86::SBB8rm:
		case X86::SHUFPDrmi:
		case X86::SHUFPSrmi:
		case X86::SQRTPDm:
		case X86::SQRTPDm_Int:
		case X86::SQRTPSm:
		case X86::SQRTPSm_Int:
		case X86::SQRTSDm:
		case X86::SQRTSDm_Int:
		case X86::SQRTSSm:
		case X86::SQRTSSm_Int:
		case X86::SUB16rm:
		case X86::SUB32rm:
		case X86::SUB64rm:
		case X86::SUB8rm:
		case X86::SUBPDrm:
		case X86::SUBPSrm:
		case X86::SUBR_F32m:
		case X86::SUBR_F64m:
		case X86::SUBR_FI16m:
		case X86::SUBR_FI32m:
		case X86::SUBR_Fp32m:
		case X86::SUBR_Fp64m:
		case X86::SUBR_Fp64m32:
		case X86::SUBR_Fp80m32:
		case X86::SUBR_Fp80m64:
		case X86::SUBR_FpI16m32:
		case X86::SUBR_FpI16m64:
		case X86::SUBR_FpI16m80:
		case X86::SUBR_FpI32m32:
		case X86::SUBR_FpI32m64:
		case X86::SUBR_FpI32m80:
		case X86::SUBSDrm:
		case X86::SUBSDrm_Int:
		case X86::SUBSSrm:
		case X86::SUBSSrm_Int:
		case X86::SUB_F32m:
		case X86::SUB_F64m:
		case X86::SUB_FI16m:
		case X86::SUB_FI32m:
		case X86::SUB_Fp32m:
		case X86::SUB_Fp64m:
		case X86::SUB_Fp64m32:
		case X86::SUB_Fp80m32:
		case X86::SUB_Fp80m64:
		case X86::SUB_FpI16m32:
		case X86::SUB_FpI16m64:
		case X86::SUB_FpI16m80:
		case X86::SUB_FpI32m32:
		case X86::SUB_FpI32m64:
		case X86::SUB_FpI32m80:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::TAILJMPm: // TAIL call
		  insertMaskBeforeTAILJMPm(MBB,MI,dl,TII,0);
		  break;
		case X86::TAILJMPm64:
		  abort();
		case X86::TCRETURNmi:
		case X86::TCRETURNmi64:
		case X86::TEST16mi:
		case X86::TEST16rm:
		case X86::TEST32mi:
		case X86::TEST32rm:
		case X86::TEST64mi32:
		case X86::TEST64rm:
		case X86::TEST8mi:
		case X86::TEST8rm:
		case X86::UCOMISDrm:
		case X86::UCOMISSrm:
		case X86::UNPCKHPDrm:
		case X86::UNPCKHPSrm:
		case X86::UNPCKLPDrm:
		case X86::UNPCKLPSrm:
		case X86::VADDPDrm:
		case X86::VADDPSrm:
		case X86::VADDSDrm:
		case X86::VADDSDrm_Int:
		case X86::VADDSSrm:
		case X86::VADDSSrm_Int:
		case X86::VADDSUBPDrm:
		case X86::VADDSUBPSrm:
		case X86::VAESDECLASTrm:
		case X86::VAESDECrm:
		case X86::VAESENCLASTrm:
		case X86::VAESENCrm:
		case X86::VAESIMCrm:
		case X86::VAESKEYGENASSIST128rm:
		case X86::VANDNPDrm:
		case X86::VANDNPSrm:
		case X86::VANDPDrm:
		case X86::VANDPSrm:
		case X86::VBLENDPDrmi:
		case X86::VBLENDPSrmi:
		case X86::VCMPPDrmi:
		case X86::VCMPPSrmi:
		case X86::VCMPSDrm:
		case X86::VCMPSDrm_alt:
		case X86::VCMPSSrm:
		case X86::VCMPSSrm_alt:
		case X86::VCVTTSD2SIrm:
		case X86::VCVTTSS2SIrm:
		case X86::VDIVPDrm:
		case X86::VDIVPSrm:
		case X86::VDIVSDrm:
		case X86::VDIVSDrm_Int:
		case X86::VDIVSSrm:
		case X86::VDIVSSrm_Int:
		case X86::VDPPDrmi:
		case X86::VDPPSrmi:
		case X86::VFsANDNPDrm:
		case X86::VFsANDNPSrm:
		case X86::VFsANDPDrm:
		case X86::VFsANDPSrm:
		case X86::VFsORPDrm:
		case X86::VFsORPSrm:
		case X86::VFsXORPDrm:
		case X86::VFsXORPSrm:
		case X86::VHADDPDrm:
		case X86::VHADDPSrm:
		case X86::VHSUBPDrm:
		case X86::VHSUBPSrm:
		case X86::VINSERTPSrm:
		case X86::VLDDQUrm:
		case X86::VMAXPDrm:
		case X86::VMAXPDrm_Int:
		case X86::VMAXPSrm:
		case X86::VMAXPSrm_Int:
		case X86::VMAXSDrm:
		case X86::VMAXSDrm_Int:
		case X86::VMAXSSrm:
		case X86::VMAXSSrm_Int:
		case X86::VMINPDrm:
		case X86::VMINPDrm_Int:
		case X86::VMINPSrm:
		case X86::VMINPSrm_Int:
		case X86::VMINSDrm:
		case X86::VMINSDrm_Int:
		case X86::VMINSSrm:
		case X86::VMINSSrm_Int:
		case X86::VMOVAPDrm:
		case X86::VMOVAPSrm:
		case X86::VMOVDDUPrm:
		case X86::VMOVDI2PDIrm:
		case X86::VMOVDI2SSrm:
		case X86::VMOVDQArm:
		case X86::VMOVDQUrm:
		case X86::VMOVDQUrm_Int:
		case X86::VMOVHPDrm:
		case X86::VMOVHPSrm:
		case X86::VMOVLPDrm:
		case X86::VMOVLPSrm:
		case X86::VMOVNTDQArm:
		case X86::VMOVQI2PQIrm:
		case X86::VMOVSDrm:
		case X86::VMOVSHDUPrm:
		case X86::VMOVSLDUPrm:
		case X86::VMOVSSrm:
		case X86::VMOVUPDrm:
		case X86::VMOVUPDrm_Int:
		case X86::VMOVUPSrm:
		case X86::VMOVUPSrm_Int:
		case X86::VMOVZDI2PDIrm:
		case X86::VMOVZPQILo2PQIrm:
		case X86::VMOVZQI2PQIrm:
		case X86::VMPSADBWrmi:
		case X86::VMULPDrm:
		case X86::VMULPSrm:
		case X86::VMULSDrm:
		case X86::VMULSDrm_Int:
		case X86::VMULSSrm:
		case X86::VMULSSrm_Int:
		case X86::VORPDrm:
		case X86::VORPSrm:
		case X86::VPABSBrm128:
		case X86::VPABSBrm64:
		case X86::VPABSDrm128:
		case X86::VPABSDrm64:
		case X86::VPABSWrm128:
		case X86::VPABSWrm64:
		case X86::VPACKSSDWrm:
		case X86::VPACKSSWBrm:
		case X86::VPACKUSDWrm:
		case X86::VPACKUSWBrm:
		case X86::VPADDBrm:
		case X86::VPADDDrm:
		case X86::VPADDQrm:
		case X86::VPADDSBrm:
		case X86::VPADDSWrm:
		case X86::VPADDUSBrm:
		case X86::VPADDUSWrm:
		case X86::VPADDWrm:
		case X86::VPANDNrm:
		case X86::VPANDrm:
		case X86::VPAVGBrm:
		case X86::VPAVGWrm:
		case X86::VPBLENDWrmi:
		case X86::VPCMPEQBrm:
		case X86::VPCMPEQDrm:
		case X86::VPCMPEQQrm:
		case X86::VPCMPEQWrm:
		case X86::VPCMPESTRIArm:
		case X86::VPCMPESTRICrm:
		case X86::VPCMPESTRIOrm:
		case X86::VPCMPESTRISrm:
		case X86::VPCMPESTRIZrm:
		case X86::VPCMPESTRIrm:
		case X86::VPCMPGTBrm:
		case X86::VPCMPGTDrm:
		case X86::VPCMPGTQrm:
		case X86::VPCMPGTWrm:
		case X86::VPCMPISTRIArm:
		case X86::VPCMPISTRICrm:
		case X86::VPCMPISTRIOrm:
		case X86::VPCMPISTRISrm:
		case X86::VPCMPISTRIZrm:
		case X86::VPCMPISTRIrm:
		case X86::VPHADDDrm128:
		case X86::VPHADDDrm64:
		case X86::VPHADDSWrm128:
		case X86::VPHADDSWrm64:
		case X86::VPHADDWrm128:
		case X86::VPHADDWrm64:
		case X86::VPHMINPOSUWrm128:
		case X86::VPHSUBDrm128:
		case X86::VPHSUBDrm64:
		case X86::VPHSUBSWrm128:
		case X86::VPHSUBSWrm64:
		case X86::VPHSUBWrm128:
		case X86::VPHSUBWrm64:
		case X86::VPINSRBrm:
		case X86::VPINSRDrm:
		case X86::VPINSRQrm:
		case X86::VPINSRWrmi:
		case X86::VPMADDUBSWrm128:
		case X86::VPMADDUBSWrm64:
		case X86::VPMADDWDrm:
		case X86::VPMAXSBrm:
		case X86::VPMAXSDrm:
		case X86::VPMAXSWrm:
		case X86::VPMAXUBrm:
		case X86::VPMAXUDrm:
		case X86::VPMAXUWrm:
		case X86::VPMINSBrm:
		case X86::VPMINSDrm:
		case X86::VPMINSWrm:
		case X86::VPMINUBrm:
		case X86::VPMINUDrm:
		case X86::VPMINUWrm:
		case X86::VPMOVSXBDrm:
		case X86::VPMOVSXBQrm:
		case X86::VPMOVSXBWrm:
		case X86::VPMOVSXDQrm:
		case X86::VPMOVSXWDrm:
		case X86::VPMOVSXWQrm:
		case X86::VPMOVZXBDrm:
		case X86::VPMOVZXBQrm:
		case X86::VPMOVZXBWrm:
		case X86::VPMOVZXDQrm:
		case X86::VPMOVZXWDrm:
		case X86::VPMOVZXWQrm:
		case X86::VPMULDQrm:
		case X86::VPMULHRSWrm128:
		case X86::VPMULHRSWrm64:
		case X86::VPMULHUWrm:
		case X86::VPMULHWrm:
		case X86::VPMULLDrm:
		case X86::VPMULLWrm:
		case X86::VPMULUDQrm:
		case X86::VPORrm:
		case X86::VPSADBWrm:
		case X86::VPSHUFBrm128:
		case X86::VPSHUFBrm64:
		case X86::VPSHUFDmi:
		case X86::VPSHUFHWmi:
		case X86::VPSHUFLWmi:
		case X86::VPSIGNBrm128:
		case X86::VPSIGNBrm64:
		case X86::VPSIGNDrm128:
		case X86::VPSIGNDrm64:
		case X86::VPSIGNWrm128:
		case X86::VPSIGNWrm64:
		case X86::VPSLLDrm:
		case X86::VPSLLQrm:
		case X86::VPSLLWrm:
		case X86::VPSRADrm:
		case X86::VPSRAWrm:
		case X86::VPSRLDrm:
		case X86::VPSRLQrm:
		case X86::VPSRLWrm:
		case X86::VPSUBBrm:
		case X86::VPSUBDrm:
		case X86::VPSUBQrm:
		case X86::VPSUBSBrm:
		case X86::VPSUBSWrm:
		case X86::VPSUBUSBrm:
		case X86::VPSUBUSWrm:
		case X86::VPSUBWrm:
		case X86::VPTESTrm:
		case X86::VPUNPCKHBWrm:
		case X86::VPUNPCKHDQrm:
		case X86::VPUNPCKHQDQrm:
		case X86::VPUNPCKHWDrm:
		case X86::VPUNPCKLBWrm:
		case X86::VPUNPCKLDQrm:
		case X86::VPUNPCKLQDQrm:
		case X86::VPUNPCKLWDrm:
		case X86::VPXORrm:
		case X86::VRCPPSm:
		case X86::VRCPPSm_Int:
		case X86::VROUNDPDm_Int:
		case X86::VROUNDPSm_Int:
		case X86::VROUNDSDm_Int:
		case X86::VROUNDSSm_Int:
		case X86::VRSQRTPSm:
		case X86::VRSQRTPSm_Int:
		case X86::VSHUFPDrmi:
		case X86::VSHUFPSrmi:
		case X86::VSQRTPDm:
		case X86::VSQRTPDm_Int:
		case X86::VSQRTPSm:
		case X86::VSQRTPSm_Int:
		case X86::VSUBPDrm:
		case X86::VSUBPSrm:
		case X86::VSUBSDrm:
		case X86::VSUBSDrm_Int:
		case X86::VSUBSSrm:
		case X86::VSUBSSrm_Int:
		case X86::VUCOMISDrm:
		case X86::VUCOMISSrm:
		case X86::VUNPCKHPDrm:
		case X86::VUNPCKHPSrm:
		case X86::VUNPCKLPDrm:
		case X86::VUNPCKLPSrm:
		case X86::VXORPDrm:
		case X86::VXORPSrm:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::WINCALL64m:
		  abort();
		case X86::XOR16rm:
		case X86::XOR32rm:
		case X86::XOR64rm:
		case X86::XOR8rm:
		case X86::XORPDrm:
		case X86::XORPSrm:
		  insertMaskBeforeLoad(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		default:
		  llvm::errs() << "inst unsupported at ";
		  abort();
		}
	  } else if(TID.mayLoad() && TID.mayStore()){ // load and store
		// these instructions load and store
		switch(MI->getOpcode()){
		case X86::ADC16mi:
		case X86::ADC16mi8:
		case X86::ADC16mr:
		case X86::ADC32mi:
		case X86::ADC32mi8:
		case X86::ADC32mr:
		case X86::ADC64mi32:
		case X86::ADC64mi8:
		case X86::ADC64mr:
		case X86::ADC8mi:
		case X86::ADC8mr:
		case X86::ADD16mi:
		case X86::ADD16mi8:
		case X86::ADD16mr:
		case X86::ADD32mi:
		case X86::ADD32mi8:
		case X86::ADD32mr:
		case X86::ADD64mi32:
		case X86::ADD64mi8:
		case X86::ADD64mr:
		case X86::ADD8mi:
		case X86::ADD8mr:
		case X86::AND16mi:
		case X86::AND16mi8:
		case X86::AND16mr:
		case X86::AND32mi:
		case X86::AND32mi8:
		case X86::AND32mr:
		case X86::AND64mi32:
		case X86::AND64mi8:
		case X86::AND64mr:
		case X86::AND8mi:
		case X86::AND8mr:
		  insertMaskBeforeStore(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		case X86::ATOMADD6432:
		case X86::ATOMAND16:
		case X86::ATOMAND32:
		case X86::ATOMAND64:
		case X86::ATOMAND6432:
		case X86::ATOMAND8:
		case X86::ATOMMAX16:
		case X86::ATOMMAX32:
		case X86::ATOMMAX64:
		case X86::ATOMMIN16:
		case X86::ATOMMIN32:
		case X86::ATOMMIN64:
		case X86::ATOMNAND16:
		case X86::ATOMNAND32:
		case X86::ATOMNAND64:
		case X86::ATOMNAND6432:
		case X86::ATOMNAND8:
		case X86::ATOMOR16:
		case X86::ATOMOR32:
		case X86::ATOMOR64:
		case X86::ATOMOR6432:
		case X86::ATOMOR8:
		case X86::ATOMSUB6432:
		case X86::ATOMSWAP6432:
		case X86::ATOMUMAX16:
		case X86::ATOMUMAX32:
		case X86::ATOMUMAX64:
		case X86::ATOMUMIN16:
		case X86::ATOMUMIN32:
		case X86::ATOMUMIN64:
		case X86::ATOMXOR16:
		case X86::ATOMXOR32:
		case X86::ATOMXOR64:
		case X86::ATOMXOR6432:
		case X86::ATOMXOR8:
		  abort();
		case X86::CLFLUSH:
		  break;
		case X86::CMPXCHG16rm:
		case X86::CMPXCHG32rm:
		case X86::CMPXCHG64rm:
		case X86::CMPXCHG8rm:
		case X86::DEC16m:
		case X86::DEC32m:
		case X86::DEC64_16m:
		case X86::DEC64_32m:
		case X86::DEC64m:
		case X86::DEC8m:
		case X86::INC16m:
		case X86::INC32m:
		case X86::INC64_16m:
		case X86::INC64_32m:
		case X86::INC64m:
		case X86::INC8m:
		case X86::LCMPXCHG16:
		case X86::LCMPXCHG32:
		case X86::LCMPXCHG64:
		case X86::LCMPXCHG8:
		case X86::LCMPXCHG8B:
		case X86::LDMXCSR:
		case X86::LFENCE:
		case X86::LOCK_ADD16mi:
		case X86::LOCK_ADD16mi8:
		case X86::LOCK_ADD16mr:
		case X86::LOCK_ADD32mi:
		case X86::LOCK_ADD32mi8:
		case X86::LOCK_ADD32mr:
		case X86::LOCK_ADD64mi32:
		case X86::LOCK_ADD64mi8:
		case X86::LOCK_ADD64mr:
		case X86::LOCK_ADD8mi:
		case X86::LOCK_ADD8mr:
		case X86::LOCK_DEC16m:
		case X86::LOCK_DEC32m:
		case X86::LOCK_DEC64m:
		case X86::LOCK_DEC8m:
		case X86::LOCK_INC16m:
		case X86::LOCK_INC32m:
		case X86::LOCK_INC64m:
		case X86::LOCK_INC8m:
		case X86::LOCK_SUB16mi:
		case X86::LOCK_SUB16mi8:
		case X86::LOCK_SUB16mr:
		case X86::LOCK_SUB32mi:
		case X86::LOCK_SUB32mi8:
		case X86::LOCK_SUB32mr:
		case X86::LOCK_SUB64mi32:
		case X86::LOCK_SUB64mi8:
		case X86::LOCK_SUB64mr:
		case X86::LOCK_SUB8mi:
		case X86::LOCK_SUB8mr:
		case X86::LXADD16:
		case X86::LXADD32:
		case X86::LXADD64:
		case X86::LXADD8:
		case X86::MASKMOVDQU:
		case X86::MASKMOVDQU64:
		case X86::MFENCE:
		case X86::MMX_EMMS:
		case X86::MMX_FEMMS:
		case X86::MMX_MASKMOVQ:
		case X86::MMX_MASKMOVQ64:
		case X86::MMX_MOVNTQmr:
		case X86::MONITOR:
		case X86::MOVDQUmr_Int:
		case X86::MOVLQ128mr:
		case X86::MOVNTDQmr_Int:
		case X86::MOVNTImr_Int:
		case X86::MOVNTPDmr_Int:
		case X86::MOVNTPSmr_Int:
		case X86::MOVUPDmr_Int:
		case X86::MOVUPSmr_Int:
		case X86::MWAIT:
		case X86::NEG16m:
		case X86::NEG32m:
		case X86::NEG64m:
		case X86::NEG8m:
		case X86::NOT16m:
		case X86::NOT32m:
		case X86::NOT64m:
		case X86::NOT8m:
		case X86::OR16mi:
		case X86::OR16mi8:
		case X86::OR16mr:
		case X86::OR32mi:
		case X86::OR32mi8:
		case X86::OR32mr:
		case X86::OR64mi32:
		case X86::OR64mi8:
		case X86::OR64mr:
		case X86::OR8mi:
		case X86::OR8mr:
		  insertMaskBeforeStore(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;		  
		case X86::PREFETCHNTA:
		case X86::PREFETCHT0:
		case X86::PREFETCHT1:
		case X86::PREFETCHT2:
		  break;
		case X86::REP_MOVSB:
		case X86::REP_MOVSD:
		case X86::REP_MOVSQ:
		case X86::REP_MOVSW:
		  insertMaskBeforeREP_MOVSX(MBB,MI,dl,TII);
		  break;
		case X86::ROL16m1:
		case X86::ROL16mCL:
		case X86::ROL16mi:
		case X86::ROL32m1:
		case X86::ROL32mCL:
		case X86::ROL32mi:
		case X86::ROL64m1:
		case X86::ROL64mCL:
		case X86::ROL64mi:
		case X86::ROL8m1:
		case X86::ROL8mCL:
		case X86::ROL8mi:
		case X86::ROR16m1:
		case X86::ROR16mCL:
		case X86::ROR16mi:
		case X86::ROR32m1:
		case X86::ROR32mCL:
		case X86::ROR32mi:
		case X86::ROR64m1:
		case X86::ROR64mCL:
		case X86::ROR64mi:
		case X86::ROR8m1:
		case X86::ROR8mCL:
		case X86::ROR8mi:
		case X86::SAR16m1:
		case X86::SAR16mCL:
		case X86::SAR16mi:
		case X86::SAR32m1:
		case X86::SAR32mCL:
		case X86::SAR32mi:
		case X86::SAR64m1:
		case X86::SAR64mCL:
		case X86::SAR64mi:
		case X86::SAR8m1:
		case X86::SAR8mCL:
		case X86::SAR8mi:
		case X86::SBB16mi:
		case X86::SBB16mi8:
		case X86::SBB16mr:
		case X86::SBB32mi:
		case X86::SBB32mi8:
		case X86::SBB32mr:
		case X86::SBB64mi32:
		case X86::SBB64mi8:
		case X86::SBB64mr:
		case X86::SBB8mi:
		case X86::SBB8mr:
		case X86::SFENCE:
		case X86::SHL16m1:
		case X86::SHL16mCL:
		case X86::SHL16mi:
		case X86::SHL32m1:
		case X86::SHL32mCL:
		case X86::SHL32mi:
		case X86::SHL64m1:
		case X86::SHL64mCL:
		case X86::SHL64mi:
		case X86::SHL8m1:
		case X86::SHL8mCL:
		case X86::SHL8mi:
		case X86::SHLD16mrCL:
		case X86::SHLD16mri8:
		case X86::SHLD32mrCL:
		case X86::SHLD32mri8:
		case X86::SHLD64mrCL:
		case X86::SHLD64mri8:
		case X86::SHR16m1:
		case X86::SHR16mCL:
		case X86::SHR16mi:
		case X86::SHR32m1:
		case X86::SHR32mCL:
		case X86::SHR32mi:
		case X86::SHR64m1:
		case X86::SHR64mCL:
		case X86::SHR64mi:
		case X86::SHR8m1:
		case X86::SHR8mCL:
		case X86::SHR8mi:
		case X86::SHRD16mrCL:
		case X86::SHRD16mri8:
		case X86::SHRD32mrCL:
		case X86::SHRD32mri8:
		case X86::SHRD64mrCL:
		case X86::SHRD64mri8:
		case X86::STMXCSR:
		case X86::SUB16mi:
		case X86::SUB16mi8:
		case X86::SUB16mr:
		case X86::SUB32mi:
		case X86::SUB32mi8:
		case X86::SUB32mr:
		case X86::SUB64mi32:
		case X86::SUB64mi8:
		case X86::SUB64mr:
		case X86::SUB8mi:
		case X86::SUB8mr:
		case X86::VLDMXCSR:
		case X86::VMASKMOVDQU:
		case X86::VMASKMOVDQU64:
		case X86::VMOVDQUmr_Int:
		case X86::VMOVLQ128mr:
		case X86::VMOVNTDQmr_Int:
		case X86::VMOVNTPDmr_Int:
		case X86::VMOVNTPSmr_Int:
		case X86::VMOVUPDmr_Int:
		case X86::VMOVUPSmr_Int:
		case X86::VSTMXCSR:
		case X86::XADD16rm:
		case X86::XADD32rm:
		case X86::XADD64rm:
		case X86::XADD8rm:
		case X86::XCHG16rm:
		case X86::XCHG32rm:
		case X86::XCHG64rm:
		case X86::XCHG8rm:
		case X86::XOR16mi:
		case X86::XOR16mi8:
		case X86::XOR16mr:
		case X86::XOR32mi:
		case X86::XOR32mi8:
		case X86::XOR32mr:
		case X86::XOR64mi32:
		case X86::XOR64mi8:
		case X86::XOR64mr:
		case X86::XOR8mi:
		case X86::XOR8mr:
		  insertMaskBeforeStore(MBB,MI,dl,TII,getMemIndex(MI));
		  if(MI->modifiesRegister(X86::ESP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
		  if(MI->modifiesRegister(X86::EBP, TRI))
			insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		  break;
		default:
		  llvm::errs() << "inst unsupported\n";
		  abort();
		}
	  } else { // MI does not load or store
		// no need to sandbox %ebp after movl %esp, %ebp
		if(MI->getOpcode() == X86::MOV32rr && MI->getOperand(0).getReg() == X86::EBP &&
		   MI->getOperand(1).getReg() == X86::ESP)
		  continue;
		// we do not sandbox store address using %ebp and a displacement to compute address
		// instead, we use guard region and sandbox the change of %ebp
		if(MI->modifiesRegister(X86::EBP,TRI))
		  insertMaskAfterReg(MBB,MI,dl,TII,X86::EBP);
		if(MI->modifiesRegister(X86::ESP,TRI))
		  insertMaskAfterReg(MBB,MI,dl,TII,X86::ESP);
	  }
	}
  }
  if(F.getFunction()->getName() == "FunGaloisCyc"){
	llvm::errs() <<"after X86SFIOptPass\n";
	F.getBlockNumbered(49)->dump();
  }
  return true;
}

FunctionPass* llvm::createX86SFIOptPass(X86TargetMachine& tm){
  return new X86SFIOptPass(tm);
}
#endif

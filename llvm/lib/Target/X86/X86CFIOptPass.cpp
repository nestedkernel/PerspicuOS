///===----- X86CFIOptPass - Control Flow Integrity optimization pass -----===//
// By Bin Zeng, Lehigh University CSE Dept.

#include "X86.h"
#include "X86CFIOptPass.h"
#include "llvm/Pass.h"
#include "llvm/Function.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/ADT/ilist.h"
#include "llvm/ADT/ilist_node.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/DenseMapInfo.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/DebugLoc.h"

using namespace llvm;

char X86CFIOptPass::ID = 0;

X86CFIOptPass::X86CFIOptPass(X86TargetMachine &tm):MachineFunctionPass(ID), TM(tm) {}

const char *X86CFIOptPass::getPassName() const {
  return "X86 CFI optimizer";
}
	

void X86CFIOptPass::getAnalysisUsage(AnalysisUsage &AU) const {
  //llvm::errs() << "X86CFIOptPass::getAnalysisUsage()\n";
  MachineFunctionPass::getAnalysisUsage(AU);
}


	// insert a check before CAll32r
void X86CFIOptPass::insertCheckCall32r(MachineBasicBlock& MBB, MachineInstr* MI,
									   DebugLoc& dl, const TargetInstrInfo* TII,
									   MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::CALL32r && "opcode: CALL32r expected");
  unsigned reg = MI->getOperand(0).getReg();
  // CMP32mi 3(reg), $CFI_ID
  BuildMI(MBB,MI,dl,TII->get(X86::CMP32mi))
	.addReg(reg).addImm(1).addReg(0).addImm(3).addReg(0).addImm(CFI_ID);
  // JNE_4 EMBB
  BuildMI(MBB,MI,dl,TII->get(X86::JNE_4)).addMBB(EMBB);
  // MBB.addSuccessor(EMBB);
  // addl 7, reg to skip prefetchnta. prefetchnta has 7 bytes
  if(skipID)BuildMI(MBB,MI,dl,TII->get(X86::ADD32ri),reg).addReg(reg).addImm(7);
}

// insert a check before CALL64r
void X86CFIOptPass::insertCheckCall64r(MachineBasicBlock& MBB, MachineInstr* MI,
									   DebugLoc& dl, const TargetInstrInfo* TII,
									   MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::CALL64r && "opcode: CALL64r expected");
  assert(false && "64 bit not supported");
}

	// insert a check before CALL32m
void X86CFIOptPass::insertCheckCall32m(MachineBasicBlock& MBB, MachineInstr* MI,
									   DebugLoc& dl, const TargetInstrInfo* TII,
									   MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::CALL32m && "opcode: CALL32m expected");
  // use %eax since %eax is caller-saved
  // MOV32rm, %eax, mem_loc
  BuildMI(MBB,MI,dl,TII->get(X86::MOV32rm),X86::EAX)
	.addReg(MI->getOperand(0).getReg()).addImm(MI->getOperand(1).getImm())
	.addReg(MI->getOperand(2).getReg()).addOperand(MI->getOperand(3))
	.addReg(MI->getOperand(4).getReg());
  // CMP32mi 3(%eax), $CFI_ID
  BuildMI(MBB,MI,dl,TII->get(X86::CMP32mi)).addReg(X86::EAX)
	.addImm(1).addReg(0).addImm(3).addReg(0).addImm(CFI_ID);
  // JNE_4 EMBB
  BuildMI(MBB,MI,dl,TII->get(X86::JNE_4)).addMBB(EMBB);
  // MBB.addSuccessor(EMBB);
  // addl 7, %eax; to skip prefetchnta
  if(skipID)BuildMI(MBB,MI,dl,TII->get(X86::ADD32ri),X86::EAX).addReg(X86::EAX).addImm(7);
  // call %eax
  BuildMI(MBB,MI,dl,TII->get(X86::CALL32r)).addReg(X86::EAX);
  MBB.erase(MI);
}

	
// insert a check before CALL64m
void X86CFIOptPass::insertCheckCall64m(MachineBasicBlock& MBB, MachineInstr* MI,
									   DebugLoc& dl, const TargetInstrInfo* TII,
									   MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::CALL64m && "opcode: CALL64m expected");
  assert(false && "64 bit not supported");
}

// insert a check before JMP32r
void X86CFIOptPass::insertCheckJmp32r(MachineBasicBlock& MBB, MachineInstr *MI,
									  DebugLoc& dl, const TargetInstrInfo* TII,
									  MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::JMP32r && "opcode: JMP32r expected");
  const unsigned reg = MI->getOperand(0).getReg();
  // CMP32mi 3(reg), $CFI_ID
  BuildMI(MBB,MI,dl,TII->get(X86::CMP32mi)).addReg(reg)
	.addImm(1).addReg(0).addImm(3).addReg(0).addImm(CFI_ID);
  // JNE_4 EMBB
  BuildMI(MBB,MI,dl,TII->get(X86::JNE_4)).addMBB(EMBB);
  // MBB.addSuccessor(EMBB);
  // addl 7, reg
  if(skipID) BuildMI(MBB,MI,dl,TII->get(X86::ADD32ri),reg).addReg(reg).addImm(7);
}

void X86CFIOptPass::insertCheckJmp64r(MachineBasicBlock& MBB, MachineInstr* MI,
									  DebugLoc& dl, const TargetInstrInfo* TII,
									  MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::JMP64r && "opcode: JMP64r expected");
  assert(false && "64 bit not supported");
}

// insert a check before JMP32m
//!!!!!!!!!!! This function has a problem with the instructions inserted
void X86CFIOptPass::insertCheckJmp32m(MachineBasicBlock& MBB, MachineInstr* MI,
									  DebugLoc& dl, const TargetInstrInfo* TII,
									  MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::JMP32m && "opcode: JMP32m expected");
  const TargetRegisterInfo* TRI = MI->getParent()->getParent()->getTarget().getRegisterInfo();
  //llvm::errs() << "insertCheckJmp32m\n";
  //unsigned killed = getRegisterKilled(MI);
#if 0
  unsigned killed = llvm::X86SFIOptPass::findDeadReg(MI, 0);
#else
  unsigned killed = 0;
#endif
  if(killed != 0){ // if the JMP32m kills a register, use it for check
    // MOV32rm, %killed, mem_loc
    BuildMI(MBB,MI,dl,TII->get(X86::MOV32rm),killed)
      .addReg(MI->getOperand(0).getReg()).addImm(MI->getOperand(1).getImm())
      .addReg(MI->getOperand(2).getReg()).addOperand(MI->getOperand(3))
      .addReg(MI->getOperand(4).getReg());
    // CMP32mi 3(%killed), $CFI_ID
    BuildMI(MBB,MI,dl,TII->get(X86::CMP32mi)).addReg(killed)
	  .addImm(1).addReg(0).addImm(3).addReg(0).addImm(CFI_ID);
    // JNE_4 EMBB
    BuildMI(MBB,MI,dl,TII->get(X86::JNE_4)).addMBB(EMBB);
	// MBB.addSuccessor(EMBB);
    // ADD32ri %killed, $7
    if(skipID) BuildMI(MBB,MI,dl,TII->get(X86::ADD32ri),killed).addReg(killed).addImm(7);
    // JMP32r %killed
    BuildMI(MBB,MI,dl,TII->get(X86::JMP32r)).addReg(killed);
    MBB.erase(MI);
  } else { // spill a register onto stack
	llvm::errs() << "Jmp32m needs a dead reg for CFI\n";
	MI->getParent()->getParent()->dump();
	abort();
    unsigned reg = 0;
    if(!MI->readsRegister(X86::AH, TRI) && !MI->readsRegister(X86::AL, TRI) &&
	   !MI->readsRegister(X86::AX, TRI) && !MI->readsRegister(X86::EAX, TRI))
      reg = X86::EAX;
    else if(!MI->readsRegister(X86::CH, TRI) && !MI->readsRegister(X86::CL, TRI) &&
			!MI->readsRegister(X86::CX, TRI) && !MI->readsRegister(X86::ECX, TRI))
      reg = X86::ECX;
    else if(!MI->readsRegister(X86::DH, TRI) && !MI->readsRegister(X86::DL, TRI) &&
			!MI->readsRegister(X86::DX, TRI) && !MI->readsRegister(X86::EDX, TRI))
      reg = X86::EDX;
    else if(!MI->readsRegister(X86::BH, TRI) && !MI->readsRegister(X86::BL, TRI) &&
			!MI->readsRegister(X86::BX, TRI) && !MI->readsRegister(X86::EBX, TRI))
      reg = X86::EBX;
	else if(!MI->readsRegister(X86::SI, TRI) && !MI->readsRegister(X86::ESI, TRI))
	  reg = X86::ESI;
	else if(!MI->readsRegister(X86::DI, TRI) && !MI->readsRegister(X86::EDI, TRI))
	  reg = X86::EDI;
    else abort();
    // pushl %reg
    BuildMI(MBB,MI,dl,TII->get(X86::PUSH32r)).addReg(reg);
    // MOV32rm  mem_loc, %reg
    BuildMI(MBB,MI,dl,TII->get(X86::MOV32rm),reg)
      .addReg(MI->getOperand(0).getReg())  // base
	  .addImm(MI->getOperand(1).getImm())  // scale
      .addReg(MI->getOperand(2).getReg())  // index
	  .addOperand(MI->getOperand(3))       // displacement
      .addReg(MI->getOperand(4).getReg()); //segment register
    // CMP32mi 3(%reg), $CFI_ID
    BuildMI(MBB,MI,dl,TII->get(X86::CMP32mi))
      .addReg(reg).addImm(1).addReg(0).addImm(3).addReg(0).addImm(CFI_ID);
    // POP32r %reg
    BuildMI(MBB,MI,dl,TII->get(X86::POP32r),reg);
    // JNE_4 EMBB
    BuildMI(MBB,MI,dl,TII->get(X86::JNE_4)).addMBB(EMBB);
  } 
}

void X86CFIOptPass::insertCheckTailJmpm(MachineBasicBlock& MBB, MachineInstr* MI,
										DebugLoc& dl, const TargetInstrInfo* TII,
										MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::TAILJMPm && "opcode: TAILJMPm expected");
  // movl mem_loc, %ecx, we use %ecx since %ecx is not used for return values
  BuildMI(MBB,MI,dl,TII->get(X86::MOV32rm), X86::ECX)
	.addReg(MI->getOperand(0).getReg()).addImm(MI->getOperand(1).getImm())
	.addReg(MI->getOperand(2).getReg()).addOperand(MI->getOperand(3))
	.addReg(MI->getOperand(4).getReg());
  // CMP32mi 3(%ecx), $CFI_ID
  BuildMI(MBB,MI,dl,TII->get(X86::CMP32mi)).addReg(X86::ECX)
	.addImm(1).addReg(0).addImm(3).addReg(0).addImm(CFI_ID);
  // JNE_4 EMBB
  BuildMI(MBB,MI,dl,TII->get(X86::JNE_4)).addMBB(EMBB);
  // MBB.addSuccessor(EMBB);
  // ADD32ri %ecx, $7
  if(skipID) BuildMI(MBB,MI,dl,TII->get(X86::ADD32ri),X86::ECX).addReg(X86::ECX).addImm(7);
  // JMP32r %ecx
  BuildMI(MBB,MI,dl,TII->get(X86::JMP32r)).addReg(X86::ECX);
  MBB.erase(MI);
}
// insert a check before TAILJMPr instruction
void X86CFIOptPass::insertCheckTailJmpr(MachineBasicBlock& MBB, MachineInstr* MI,
										DebugLoc& dl, const TargetInstrInfo* TII,
										MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::TAILJMPr && "opcode TAILJMPr expected");
  unsigned reg = MI->getOperand(0).getReg();
  // CMP32mi 3(reg), $CFI_ID
  BuildMI(MBB,MI,dl,TII->get(X86::CMP32mi)).addReg(reg)
	.addImm(1).addReg(0).addImm(3).addReg(0).addImm(CFI_ID);
  BuildMI(MBB,MI,dl,TII->get(X86::JNE_4)).addMBB(EMBB); // JNE_4 EMBB
  // MBB.addSuccessor(EMBB);
  //addl 7, reg
  if(skipID) BuildMI(MBB,MI,dl,TII->get(X86::ADD32ri),reg).addReg(reg).addImm(7); 
}

  
// return the first register that is killed by the instruction MI
unsigned X86CFIOptPass::getRegisterKilled(MachineInstr* const MI){
  for(unsigned i = 0, num = MI->getNumOperands(); i < num; ++i){
    MachineOperand mop = MI->getOperand(i);
    if(!mop.isReg())
      continue;
    if(mop.isKill())
      return mop.getReg();
  }
  return 0;
}

// insert a check before JMP64m
void X86CFIOptPass::insertCheckJmp64m(MachineBasicBlock& MBB, MachineInstr* MI,
									  DebugLoc& dl, const TargetInstrInfo* TII,
									  MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::JMP64m && "opcode: JMP64m expected");
  assert(false && "64 bit not supported");
}
	
// insert a check before ret using cdecl calling convention
// %ecx is used for comparision
void X86CFIOptPass::insertCheckRet(MachineBasicBlock& MBB, MachineInstr* MI,
								   DebugLoc& dl, const TargetInstrInfo* TII,
								   MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::RET && "opcode: RET expected");
  if((MI->getParent()->getParent()->getFunction()->getName()).equals("main"))
	return;
  // movl (%esp), %ecx, we use %ecx since %ecx is not used for return values
  BuildMI(MBB,MI,dl,TII->get(X86::MOV32rm), X86::ECX)
	.addReg(X86::ESP).addImm(1).addReg(0).addImm(0).addReg(0);
  // addl 4, %esp
  BuildMI(MBB,MI,dl,TII->get(X86::ADD32ri),X86::ESP)
	.addReg(X86::ESP).addImm(4);
  // cmpl $CFI_ID, 3(%ecx)
  BuildMI(MBB,MI,dl,TII->get(X86::CMP32mi)).addReg(X86::ECX)
	.addImm(1).addReg(0).addImm(3).addReg(0).addImm(CFI_ID);
  // jne EMBB
  BuildMI(MBB,MI,dl,TII->get(X86::JNE_4)).addMBB(EMBB);
  // MBB.addSuccessor(EMBB);
  // addl $7, %ecx
  if(skipID) BuildMI(MBB,MI,dl,TII->get(X86::ADD32ri),X86::ECX).addReg(X86::ECX).addImm(7);
  // jmp %ecx
  BuildMI(MBB,MI,dl,TII->get(X86::JMP32r)).addReg(X86::ECX);
  // erase removes the node from the list and recycle the memory
  MI->eraseFromParent(); // MBB.erase(MI);
}
	
// insert a check before reti using cdecl calling convention
// %ecx is used for comparison
void X86CFIOptPass::insertCheckReti(MachineBasicBlock& MBB, MachineInstr* MI,
									DebugLoc& dl, const TargetInstrInfo* TII,
									MachineBasicBlock* EMBB){
  assert(MI->getOpcode() == X86::RETI && "opcode: RETI expected");
  // MOV32rm %ecx, (%esp); we use %ecx since %ecx is not used for return values
  BuildMI(MBB,MI,dl,TII->get(X86::MOV32rm),X86::ECX)
	.addReg(X86::ESP).addImm(1).addReg(0).addImm(0).addReg(0);
  // add imm+4, %esp
  BuildMI(MBB,MI,dl,TII->get(X86::ADD32ri),X86::ESP)
	.addReg(X86::ESP).addImm(MI->getOperand(0).getImm()+4);
  // cmpl $CFI_ID, 3(%ecx)
  BuildMI(MBB,MI,dl,TII->get(X86::CMP32mi)).addReg(X86::ECX)
	.addImm(1).addReg(0).addImm(3).addReg(0).addImm(CFI_ID);
  // jne EMBB
  BuildMI(MBB,MI,dl,TII->get(X86::JNE_4)).addMBB(EMBB);
  // MBB.addSuccessor(EMBB);
  // addl $7, %ecx
  if(skipID) BuildMI(MBB,MI,dl,TII->get(X86::ADD32ri),X86::ECX)
	.addReg(X86::ECX).addImm(7);
  // jmp %ecx
  BuildMI(MBB,MI,dl,TII->get(X86::JMP32r)).addReg(X86::ECX);
  // delete reti instruction
  MBB.erase(MI);
}

// insert prefetchnta $CFI_ID
void X86CFIOptPass::insertIDFunction(MachineFunction& F,DebugLoc & dl, 
									 const TargetInstrInfo* TII){
  // main function does not need ID
  if((F.getFunction()->getName()).equals("main")) return;
  MachineBasicBlock& MBB = *(F.begin());
  MachineInstr* MI = MBB.begin();
  // prefetchnta CFI_ID
  BuildMI(MBB,MI,dl,TII->get(X86::PREFETCHNTA))
	.addReg(0).addImm(0).addReg(0).addImm(CFI_ID).addReg(0);
}

// insert prefetchnta $CFI_ID at the beginning of MBB
void X86CFIOptPass::insertIDBasicBlock(MachineBasicBlock& MBB,
									   DebugLoc& dl, const TargetInstrInfo* TII){
  MachineInstr * MI = MBB.begin();
  BuildMI(MBB,MI,dl,TII->get(X86::PREFETCHNTA))
	.addReg(0).addImm(0).addReg(0).addImm(CFI_ID).addReg(0);
}

// insert prefetchnta CFI_ID at the beginning of MBB's successors
void X86CFIOptPass::insertIDSuccessors(MachineBasicBlock & MBB,
									   DebugLoc& dl, const TargetInstrInfo* TII){
  if(!MBB.succ_empty()){ // insert prefetchnta ID at the beginning of successors
    for(MachineBasicBlock::succ_iterator SI = MBB.succ_begin(), E = MBB.succ_end();
		SI != E; ++SI){
      MachineBasicBlock& MBBS = (**SI);
      MachineInstr * MI = MBBS.begin();
      BuildMI(MBBS,MI,dl,TII->get(X86::PREFETCHNTA))
		.addReg(0).addImm(0).addReg(0).addImm(CFI_ID).addReg(0);
    }
  } else { llvm::errs() << "error: jmp target not found\n"; abort(); }
}

// insert prefetchnta after call instruction
// MI points to the call instruction
// nextMI points to the next instruction
void X86CFIOptPass::insertIDCall(MachineBasicBlock & MBB, MachineInstr* MI,
								 MachineInstr* next, DebugLoc& dl,
								 const TargetInstrInfo* TII){
  assert(MI->getDesc().isCall());
  // for instrutions like this: CALLpcrel32 exit/abort
  // no need to insert prefetchnta
  if(MI->getParent()->succ_empty() &&
	 MI == &*(MI->getParent()->rbegin()) &&
	 MI->getOpcode() == X86::CALLpcrel32 )
	return;
	 
  // prefetchnta $CFI_ID
  BuildMI(MBB,next,dl,TII->get(X86::PREFETCHNTA))
	.addReg(0).addImm(0).addReg(0).addImm(CFI_ID).addReg(0);
}

// insert a machine basic block with the error_label into MF and before I
// Pred is the logical predecessor of the MachineBasicBlock to be inserted
// the new basic block is inserted right before I
MachineBasicBlock* X86CFIOptPass::insertBasicBlockBefore(MachineFunction &MF,
														 MachineFunction::iterator I){
  MachineBasicBlock * MBB = MF.CreateMachineBasicBlock(NULL);
  MBB->setNumber(MF.addToMBBNumbering(MBB)); // add MBB to MBBNumbering
  // add MBB to its own successor so that
  // during dataflow analysis, the LiveOuts computation is corrent.
  MBB->addSuccessor(MBB); 
  const TargetInstrInfo *TII = MF.getTarget().getInstrInfo();
  DebugLoc dl;
  // any instruction which uses or defines registers
  // including all call instructions cause problems here
  // JNE_4 error_label
  // BuildMI(MBB,dl,TII->get(X86::JNE_4)).addExternalSymbol("error_label");
  // insert jmp 0
  BuildMI(MBB,dl,TII->get(X86::JMP_1)).addImm(0);
  // MOV32ri %eax, 0, causes problems
  // BuildMI(MBB,dl,TII->get(X86::MOV32ri),X86::EAX).addImm(0);
  // CALL32r %eax !!! this has problems when dump is used
  // I still do not know how to insert CALL instructions
  // BuildMI(MBB,dl,TII->get(X86::CALL32r)).addReg(X86::EAX);
  // call abort, causes problems
  // BuildMI(MBB,dl,TII->get(X86::CALLpcrel32)).addExternalSymbol("abort");
  MF.insert(I,MBB);
  return MBB;
}

// splitMBBAt - Given a machine basic block and an iterator into it,
// split the MBB so that the part before the iterator falls into the
// part starting at the iterator. This returns the new MBB.
MachineBasicBlock* X86CFIOptPass::splitMBBAt(MachineBasicBlock &CurMBB,
											 MachineBasicBlock::iterator BBI1){
  MachineFunction &MF = *CurMBB.getParent();
  const TargetInstrInfo *TII = MF.getTarget().getInstrInfo();
  if(!TII->isLegalToSplitMBBAt(CurMBB,BBI1))
	return 0;

  MachineFunction::iterator MBBI = &CurMBB;
  MachineBasicBlock *NewMBB = MF.CreateMachineBasicBlock(CurMBB.getBasicBlock());
  CurMBB.getParent()->insert(++MBBI, NewMBB);

  NewMBB->transferSuccessors(&CurMBB);
  CurMBB.addSuccessor(NewMBB);
  NewMBB->splice(NewMBB->end(), &CurMBB,BBI1,CurMBB.end());

  return NewMBB;
}

// returns true if MI's target is from a jump table
bool X86CFIOptPass::fromJmpTable(const MachineInstr* const MI){
  assert(MI->getOpcode() == X86::JMP32r);
  const unsigned Reg = MI->getOperand(0).getReg();
  if(!Reg) return false;
  const MachineBasicBlock& MBB = *MI->getParent();
  const TargetRegisterInfo* TRI = MBB.getParent()->getTarget().getRegisterInfo();
  MachineBasicBlock::const_iterator I(MI), E = MBB.begin();
  --I;
  while(I != E){
	if((*I).definesRegister(Reg) || (*I).modifiesRegister(Reg, TRI)){
	  for(unsigned i = 0, e = (*I).getNumOperands(); i < e; ++i)
		if((*I).getOperand(i).getType() == MachineOperand::MO_JumpTableIndex)
		  return true;
	  return false;
	}
  }
  return false;
}

// this function does the main work
bool X86CFIOptPass::runOnMachineFunction(MachineFunction &F){
  const TargetInstrInfo *TII = F.getTarget().getInstrInfo();
  DebugLoc dl;
  insertIDFunction(F,dl,TII); // insert an ID at the beginning of F

  // insert an error MachineBasicBlock at the end
  MachineBasicBlock *EMBB = insertBasicBlockBefore(F, F.end());
  // traverse all the machine basic blocks
  for(MachineFunction::iterator FI = F.begin();
	  FI != F.end(); ++FI){
	MachineBasicBlock& MBB = *FI;
	// traverse all the instructions inside the machine basic block
	for(MachineBasicBlock::iterator I = MBB.begin(); I!=MBB.end();){
	  MachineInstr* MI = I++;
	  MachineInstr* nextMI = I;
	  if(MI->getDesc().isCall() || MI->getDesc().isIndirectBranch() || MI->getDesc().isReturn()){
		switch(MI->getOpcode()){
		case X86::CALL32m:
		  insertIDCall(MBB,MI,nextMI,dl,TII);
		  insertCheckCall32m(MBB,MI,dl,TII,EMBB);
		  break;
		case X86::CALL32r:
		  insertIDCall(MBB,MI,nextMI,dl,TII);
		  insertCheckCall32r(MBB,MI,dl,TII,EMBB);
		  break;
		case X86::CALL64m:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::CALL64pcrel32:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::CALL64r:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::CALLpcrel16:
		case X86::CALLpcrel32:
		  insertIDCall(MBB,MI,nextMI,dl,TII);
		  break;
		case X86::FARCALL16i:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::FARCALL16m:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::FARCALL32i:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::FARCALL32m:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::FARCALL64:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
#if 0
		case X86::TAILJMP_1:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
#endif
		  // TAILJMPd is an direct jmp instruction
		  // when there is a call at the end of a function, it can be transformed into
		  // a jmp instruction
		case X86::TAILJMPd:
		  break;
		case X86::TAILJMPd64:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::TAILJMPm:
		  insertCheckTailJmpm(MBB,MI,dl,TII, EMBB); break;
		case X86::TAILJMPm64:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::TAILJMPr:
		  insertCheckTailJmpr(MBB,MI,dl,TII,EMBB); break;
		case X86::TAILJMPr64:
		  llvm::errs() << "instr unsupported at " << __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::TCRETURNdi:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::TCRETURNdi64:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump();  abort(); break;
		case X86::TCRETURNmi:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::TCRETURNmi64:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::TCRETURNri:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::TCRETURNri64:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
#if 0
		case X86::WINCALL64m:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::WINCALL64pcrel32:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::WINCALL64r:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
#endif
		case X86::FARJMP16i:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::FARJMP16m:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::FARJMP32i:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::FARJMP32m:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::FARJMP64:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::JMP32m:
		  // if the jmp does not jump through a jump table index insert checks and IDs
		  if(!JTOpt || MI->getOperand(3).getType() != MachineOperand::MO_JumpTableIndex){
			insertCheckJmp32m(MBB,MI,dl,TII,EMBB);
			insertIDSuccessors(MBB,dl,TII); // insert prefetchnta CFI_ID at successors
		  }
		  break;
		case X86::JMP32r:
		  /// if the JMP32r instruction is a jump table the check can be eliminated
		  if(!JTOpt || !fromJmpTable(MI)){
			insertIDSuccessors(MBB,dl,TII);
			insertCheckJmp32r(MBB,MI,dl,TII,EMBB);
		  }
		  break;
		case X86::JMP64m:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::JMP64pcrel32:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::JMP64r:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		case X86::RET:
		  insertCheckRet(MBB,MI,dl,TII,EMBB); break;
		case X86::RETI:
		  insertCheckReti(MBB,MI,dl,TII,EMBB); break;
#if 0
		case X86::LRET: // far ret
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
#endif
		case X86::LRETI: // far reti
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		default:
		  llvm::errs() << "instr unsupported at "<< __FILE__ << ":" << __LINE__ << "\n";
		  MI->dump(); abort(); break;
		}
	  }
	}
  }
  return true;
}

namespace llvm {
FunctionPass * createX86CFIOptPass(X86TargetMachine &tm) {
  return new X86CFIOptPass(tm);
}
}


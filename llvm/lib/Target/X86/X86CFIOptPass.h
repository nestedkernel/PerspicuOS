//                     Control-Flow Integrity Implementation
//
// This file was written by Bin Zeng at the Lehigh University CSE Department.
// All Right Reserved.
//
//===----------------------------------------------------------------------===//
//
// This file defines a machine language level transform that enforces control
// flow integrity.
//
//===----------------------------------------------------------------------===//

#ifndef X86CFIOPTPASS_H
#define X86CFIOPTPASS_H

#include "llvm/CodeGen/MachineFunctionPass.h"
#include "X86TargetMachine.h"

namespace llvm{

  class MachineBasicBlock;
  class MachineInstr;
  class DebugLoc;
  class TargetInstrInfo;
  class MachineFunction;
  
  struct X86CFIOptPass : public MachineFunctionPass {
    // the CFI ID
    const static int CFI_ID = 19880616;

    const static bool JTOpt  = true; // jump table index optimization
    const static bool skipID = true; // skip prefetchnta 
  
  
    // The X86 target machine
    X86TargetMachine &TM;

    // the ID of this pass
    static char ID;
    
    X86CFIOptPass(X86TargetMachine &tm);  

    virtual const char *getPassName() const;  

    virtual void getAnalysisUsage(AnalysisUsage &AU) const;

    // insert check before call32r
    void insertCheckCall32r(MachineBasicBlock& MBB, MachineInstr* MI,
              DebugLoc& dl, const TargetInstrInfo* TII,
              MachineBasicBlock* EMBB);
    //insert check before call64r
    void insertCheckCall64r(MachineBasicBlock& MBB, MachineInstr* MI,
              DebugLoc& dl, const TargetInstrInfo* TII,
              MachineBasicBlock* EMBB);
    // insert check before call32m
    void insertCheckCall32m(MachineBasicBlock& MBB, MachineInstr* MI,
              DebugLoc& dl, const TargetInstrInfo* TII,
              MachineBasicBlock* EMBB);
    // insert check before call64m
    void insertCheckCall64m(MachineBasicBlock& MBB, MachineInstr* MI,
              DebugLoc& dl, const TargetInstrInfo* TII,
              MachineBasicBlock* EMBB);
    // insert check before jmp32r
    void insertCheckJmp32r(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);
    // insert check before jmp64r
    void insertCheckJmp64r(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);
    // insert a check before JMP32m
    void insertCheckJmp32m(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);

    // insert a check before TAILJMPm
    void insertCheckTailJmpm(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);
    // insert a check before TAILJMPr
    void insertCheckTailJmpr(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);
  
    // insert a check before JMP64m
    void insertCheckJmp64m(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);

    // insert a check before ret using cdecl calling convention
    // %ecx is used for comparision
    void insertCheckRet(MachineBasicBlock& MBB, MachineInstr* MI,
            DebugLoc& dl, const TargetInstrInfo* TII,
            MachineBasicBlock* EMBB);

    // insert a check before reti using cdecl calling convention
    // %ecx is used for comparison
    void insertCheckReti(MachineBasicBlock& MBB, MachineInstr* MI,
             DebugLoc& dl, const TargetInstrInfo* TII,
             MachineBasicBlock *EMBB);

    // insert prefetchnta CFI_ID
    void insertIDFunction(MachineFunction& F, DebugLoc& dl, const TargetInstrInfo* TII);
    
    // insert prefetchnta CFI_ID at the beginning of MBB
    void insertIDBasicBlock(MachineBasicBlock& MBB,
          DebugLoc& dl, const TargetInstrInfo* TII);
    
    // insert prefetchnta CFI_ID at the beginning of the successors of MBB
    void insertIDSuccessors(MachineBasicBlock& MBB,
          DebugLoc& dl, const TargetInstrInfo* TII);

    // insert prefetchnta after call, MI points to the call instruction
    // next points to the inst after call
    void insertIDCall(MachineBasicBlock& MBB, MachineInstr* MI,
            MachineInstr* next, DebugLoc& dl,
            const TargetInstrInfo* TII);
    
    // returns the register number killed by the instruction if any
    // if there are multiple,return the first one
    // if none, return 0
    unsigned getRegisterKilled(MachineInstr* const MI);

    // insert a BasicBlock after MBB
    // the MachineBasicBlock is inserted right before I
    // return the pointer to the new MachineBasicBlock
    MachineBasicBlock* insertBasicBlockBefore(MachineFunction& MF,
                          MachineFunction::iterator I);
  
    // splitMBBAt - Given a machine basic block and an iterator
    // into it, split the MBB so that the part before the
    // iterator falls into the part starting at the iterator.
    // This returns the new MBB
    MachineBasicBlock* splitMBBAt(MachineBasicBlock &CurMBB,
                  MachineBasicBlock::iterator BBI1);

    // returns true if the register used by this instruction is from
    // a jump table entry
    bool fromJmpTable(const MachineInstr* const MI);
  
    virtual bool runOnMachineFunction(MachineFunction &F);

#if 0
    // insert the error label BasicBlock
    void insertErrorLabel();

  
    // do initialization on the module before optimization
    bool doInitialization(Module &M);

    // the function that does the real work
    bool runOnMachineFunction(MachineFunction &MF);

    // do some finalization after optimization is finished
    bool doFinalization(Module &M);
#endif
  };

}

#endif

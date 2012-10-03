//===-- X86CFIAlignPass.h - CFI Alignment Pass for Intel X86 --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a Machine Function pass that adds NOP padding instructions
// so that all instructions are aligned properly for control-flow integrity
// (CFI).
//
//===----------------------------------------------------------------------===//

#include "llvm/CodeGen/MachineFunctionPass.h"
#include "X86TargetMachine.h"

namespace llvm {
  struct X86CFIAlignPass : public MachineFunctionPass {
    public:
      // The pass identifier
      static char ID;

      // Pass constructor
      X86CFIAlignPass (X86TargetMachine & tm) : MachineFunctionPass(ID) {
        return;
      }

      // Return the name of the pass
      const char * getPassName(void) const {
        return "X86 CFI Alignment Pass";
      }

      // Get analysis passed needed and preserved by this pass
      virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        // This pass does not modify the control-flow graph of the function
        AU.setPreservesCFG();
        return;
      }

      virtual bool runOnMachineFunction (MachineFunction &F);
  };
}


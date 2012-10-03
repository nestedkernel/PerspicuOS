//===-- X86CFIAlignPass.cpp - CFI Alignment Pass for Intel X86 ------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the methods for a Machine Function pass that adds NOP
// padding instructions so that all instructions are aligned properly for
// control-flow integrity (CFI).  This ensures that the labels used for CFI
// do not appear anywhere else in the code segment.
//
//===----------------------------------------------------------------------===//

#include "X86CFIAlignPass.h"

#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"

#include <algorithm>
#include <vector>

using namespace llvm;

// Variable to hold the identifier assigned to this pass
char X86CFIAlignPass::ID = 0;

//
// Function: processMacineBB()
//
// Description:
//  Scan through each instruction and pad it if necessary.
//
static void
processMachineBB (MachineBasicBlock &  MBB) {
  //
  // Get target information for creating new instructions.
  //
  const TargetInstrInfo *TII = MBB.getParent()->getTarget().getInstrInfo();

  //
  // Create a local container to hold all of the currently existing machine
  // instructions.  We don't want to pad the padding instructions.
  //
  std::vector<MachineInstr *> Worklist;

  //
  // Go find all the instructions that need alignment.
  //
  MachineBasicBlock::instr_iterator i = MBB.instr_begin();
  MachineBasicBlock::instr_iterator e = MBB.instr_end();
  for (; i != e; ++i) {
    //
    // Determine whether the instruction needs to be padded.
    //
    MachineInstr * MI = i;
    unsigned instructionLength = MI->getDesc().getSize();
    if ((instructionLength % 8) != 0) {
      for (unsigned index = 0; index < 8 - (instructionLength % 8); ++index) {
        BuildMI (MBB, MI, MI->getDebugLoc(), TII->get(X86::NOOP));
      }
    }
  }

  //
  // Process each machine instruction.
  //
  return;
}

//
// Method: runOnMachineFunction()
//
// Description:
//  This method is called by the pass manager when it needs to use this pass to
//  transform a function.  This method will modify the specified machine
//  function so that all instructions are aligned on the appropriate boundary
//  for CFI.
//
// Return value:
//  true  - The MachineFunction has been modified.
//  false - The MachineFunction has not been modified.
//
bool
X86CFIAlignPass::runOnMachineFunction (MachineFunction &F) {
  //
  // TODO: Align the beginning of the machine function.
  //
  if (F.getAlignment() < 3) F.setAlignment(3);

  //
  // Process each machine basic block.
  //
  std::for_each (F.begin(), F.end(), (processMachineBB));

  //
  // Assume that we've made some modification to the function.
  //
  return true;
}

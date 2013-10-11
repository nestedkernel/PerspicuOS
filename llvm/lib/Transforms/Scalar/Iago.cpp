//===- Iago.cpp - Instrument Code to Thwart Iago Attacks ----------------- --//
// 
//                     The LLVM Compiler Infrastructure
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
// 
//===----------------------------------------------------------------------===//
//
// This pass instruments mmap() calls to ensure that the don't return pointers
// into the ghost memory.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "sva"

#include "llvm/ADT/Statistic.h"
#include "llvm/Attributes.h"
#include "llvm/Constants.h"
#include "llvm/Pass.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Target/TargetData.h"

// Pass Statistics
namespace {
  STATISTIC (IagoChecks, "Load/Store Instrumentation Added");
}

#if 0
/* Mask to determine if we use the original value or the masked value */
static const uintptr_t checkMask = 0xffffff0000000000u;
#else
/* Mask to determine if we use the original value or the masked value */
static const uintptr_t checkMask = 0x00000000ffffff00;
#endif

/* Mask to set proper lower-order bits */
static const uintptr_t setMask   = 0x0000008000000000u;

namespace llvm {
  //
  // Pass: Iago
  //
  // Description:
  //  This pass instruments code to prevent Iago attacks.
  //
  struct Iago : public FunctionPass, InstVisitor<Iago>{
   public:
     static char ID;
     Iago() : FunctionPass(ID) {}
      virtual bool runOnFunction (Function & F);
      const char *getPassName() const {
        return "Iago Instrumentation";
      }
     
      virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        // Prerequisite passes
        AU.addRequired<TargetData>();

        // Preserve the CFG
        AU.setPreservesCFG();
        return;
      }

     // Initialization method

     // Visitor methods
     void visitCallInst (CallInst & CI);

   private:
     bool isTriviallySafe (Value * Ptr, Type * Type);
     Value * addBitMasking (Value * Pointer, Instruction & I);
     void instrumentMemcpy(Value * D, Value * S, Value * L, Instruction * I);
  };
}

using namespace llvm;

namespace llvm {

char Iago::ID = 0;

static RegisterPass<Iago>
X ("iago", "Insert Iago load/store instrumentation");

//
// Method: addBitMasking()
//
// Description:
//  Add code before the specified instruction to perform the appropriate
//  bit-masking of the specified pointer.
//
Value *
Iago::addBitMasking (Value * Pointer, Instruction & I) {
  //
  // Create the integer values used for bit-masking.
  //
  TargetData & TD = getAnalysis<TargetData>();
  Type * IntPtrTy = TD.getIntPtrType(I.getContext());
  Value * CheckMask = ConstantInt::get (IntPtrTy, checkMask);
  Value * SetMask   = ConstantInt::get (IntPtrTy, setMask);
  Value * Zero      = ConstantInt::get (IntPtrTy, 0u);
  Value * ThirtyTwo = ConstantInt::get (IntPtrTy, 32u);

  //
  // Convert the pointer into an integer and then shift the higher order bits
  // into the lower-half of the integer.  Bit-masking operations can use
  // constant operands, reducing register pressure, if the operands are 32-bits
  // or smaller.
  //
  PtrToIntInst * CastedPointer = new PtrToIntInst(Pointer, IntPtrTy, "ptr", &I);
  Value * PtrHighBits = BinaryOperator::Create (Instruction::LShr,
                                                CastedPointer,
                                                ThirtyTwo,
                                                "highbits",
                                                &I);
                                                    
#if 1
#if 1
  //
  // Create an instruction to mask off the proper bits to see if the pointer
  // is within the secure memory range.
  //
  Value * CheckMasked = BinaryOperator::Create (Instruction::And,
                                                PtrHighBits,
                                                CheckMask,
                                                "checkMask",
                                                &I);
#endif

  //
  // Compare the masked pointer to the mask.  If they're the same, we need to
  // set that bit.
  //
#if 1
  Value * Cmp = new ICmpInst (&I,
                              CmpInst::ICMP_EQ,
                              CheckMasked,
                              CheckMask,
                              "cmp");
#else
  Value * Cmp = new ICmpInst (&I,
                              CmpInst::ICMP_ULE,
                              CheckMask,
                              CastedPointer,
                              "cmp");
#endif

  //
  // Create the select instruction that, at run-time, will determine if we use
  // the bit-masked pointer or the original pointer value.
  //
  Value * MaskValue = SelectInst::Create (Cmp, SetMask, Zero, "ptr", &I);

  //
  // Create instructions that create a version of the pointer with the proper
  // bit set.
  //
  Value * Masked = BinaryOperator::Create (Instruction::Or,
                                           CastedPointer,
                                           MaskValue,
                                           "setMask",
                                           &I);

  //
  // Now replace all uses of the original instruction with this one.  Be sure
  // to fixup instructions we created that need to use the old value.
  //
  Masked = new IntToPtrInst (Masked, Pointer->getType(), "masked", &I);
  Pointer->replaceAllUsesWith (Masked);
  CastedPointer->replaceUsesOfWith (Masked, Pointer);

  return (Masked);
#else
  Module * M = I.getParent()->getParent()->getParent();
  Function * CheckFunction = cast<Function>(M->getFunction ("sva_checkptr"));
  assert (CheckFunction && "CheckFunction not found!\n");
  CallInst::Create (CheckFunction, CastedPointer, "", &I);
  return Pointer;
#endif
}

//
// Method: visitCallInst()
//
// Description:
//  Place a run-time check on functions that return pointers from the kernel.
//
void
Iago::visitCallInst (CallInst & CI) {
  //
  // Get the instruction after the call.
  //
  BasicBlock::iterator I = &CI;
  ++I;
  if (Function * F = CI.getCalledFunction()) {
    if (F->hasName() && F->getName().equals("mmap")) {
      addBitMasking (&CI, *I);
      ++IagoChecks;
    }
  }

  return;
}

bool
Iago::runOnFunction (Function & F) {
  //
  // Visit all of the instructions in the function.
  //
  visit (F);
  return true;
}

}

namespace llvm {
  FunctionPass * createIagoPass (void) {
    return new Iago();
  }
}

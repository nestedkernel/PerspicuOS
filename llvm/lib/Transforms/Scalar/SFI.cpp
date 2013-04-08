//===- SFI.cpp - Instrument loads/stores for Software Fault Isolation ----- --//
// 
//                     The LLVM Compiler Infrastructure
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
// 
//===----------------------------------------------------------------------===//
//
// This pass instruments loads and stores to prevent them from accessing
// protected regions of the virtual address space.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "sva"

#include "llvm/ADT/Statistic.h"
#include "llvm/Attributes.h"
#include "llvm/Constants.h"
#include "llvm/Pass.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Target/TargetData.h"

// Pass Statistics
namespace {
  STATISTIC (LSChecks, "Load/Store Instrumentation Added");
}

/* Mask to determine if we use the original value or the masked value */
static const uintptr_t checkMask = 0xffffff0000000000u;

/* Mask to set proper lower-order bits */
static const uintptr_t setMask = 0xffffff8000000000u;

namespace llvm {
  //
  // Pass: SFI
  //
  // Description:
  //  This pass instruments loads and stores for software fault isolation.
  //
  struct SFI : public FunctionPass, InstVisitor<SFI>{
   public:
     static char ID;
     SFI() : FunctionPass(ID) {}
      virtual bool runOnFunction (Function & F);
      const char *getPassName() const {
        return "SFI Instrumentation";
      }
     
      virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        // Prerequisite passes
        AU.addRequired<TargetData>();

        // Preserve the CFG
        AU.setPreservesCFG();
        return;
      }

     // Visitor methods
     void visitLoadInst  (LoadInst  & LI);
     void visitStoreInst (StoreInst & SI);
     void visitAtomicCmpXchgInst (AtomicCmpXchgInst &I);
     void visitAtomicRMWInst (AtomicRMWInst &I);

   private:
     bool isTriviallySafe (Value * Ptr, Type * Type);
     Value * addBitMasking (Value * Pointer, Instruction & I);
  };
}

using namespace llvm;

namespace llvm {

char SFI::ID = 0;

static RegisterPass<SFI>
X ("sfi", "Insert SFI load/store instrumentation");

//
// Method: isTriviallySafe()
//
// Description:
//  This method determines if a memory access of the specified type is safe
//  (and therefore does not need a run-time check).
//
// Inputs:
//  Ptr     - The pointer value that is being checked.
//  MemType - The type of the memory access.
//
// Return value:
//  true  - The memory access is safe and needs no run-time check.
//  false - The memory access may be unsafe and needs a run-time check.
//
// FIXME:
//  Performing this check here really breaks the separation of concerns design
//  that we try to follow; this should really be implemented as a separate
//  optimization pass.  That said, it is quicker to implement it here.
//
bool
SFI::isTriviallySafe (Value * Ptr, Type * MemType) {
  //
  // Attempt to see if this is a stack or global allocation.  If so, get the
  // allocated type.
  //
  Type * AllocatedType = 0;
  if (AllocaInst * AI = dyn_cast<AllocaInst>(Ptr->stripPointerCasts())) {
    if (!(AI->isArrayAllocation())) {
      AllocatedType = AI->getAllocatedType();
    }
  }

  if (GlobalVariable * GV=dyn_cast<GlobalVariable>(Ptr->stripPointerCasts())) {
    AllocatedType = GV->getType()->getElementType();
  }

  //
  // If this is not a stack or global object, it is unsafe (it might be
  // deallocated, for example).
  //
  if (!AllocatedType)
    return false;

  //
  // If the types are the same, then the access is safe.
  //
  if (AllocatedType == MemType)
    return true;

  //
  // Otherwise, see if the allocated type is larger than the accessed type.
  //
  TargetData & TD = getAnalysis<TargetData>();
  uint64_t AllocTypeSize = TD.getTypeAllocSize(AllocatedType);
  uint64_t MemTypeSize   = TD.getTypeStoreSize(MemType);
  return (AllocTypeSize >= MemTypeSize);
}

//
// Method: addBitMasking()
//
// Description:
//  Add code before the specified instruction to perform the appropriate
//  bit-masking of the specified pointer.
//
Value *
SFI::addBitMasking (Value * Pointer, Instruction & I) {
  //
  // Create the integer values used for bit-masking.
  //
  TargetData & TD = getAnalysis<TargetData>();
  Type * IntPtrTy = TD.getIntPtrType(I.getContext());
  Value * CheckMask = ConstantInt::get (IntPtrTy, checkMask);
  Value * SetMask   = ConstantInt::get (IntPtrTy, setMask);

  //
  // Create instructions that create a version of the pointer with the proper
  // bit set.
  //
  Value * CastedPointer = new PtrToIntInst (Pointer, IntPtrTy, "ptr", &I);
  Value * Masked = BinaryOperator::Create (Instruction::Or,
                                           CastedPointer,
                                           SetMask,
                                           "setMask",
                                           &I);
  Masked = new IntToPtrInst (Masked, Pointer->getType(), "masked", &I);

  //
  // Create an instruction to mask off the proper bits to see if the pointer
  // is within the secure memory range.
  //
  Value * CheckMasked = BinaryOperator::Create (Instruction::And,
                                                CastedPointer,
                                                CheckMask,
                                                "checkMask",
                                                &I);

  //
  // Compare the masked pointer to the mask.  If they're the same, we need to
  // set that bit.
  //
  Value * Cmp = new ICmpInst (&I,
                              CmpInst::ICMP_EQ,
                              CheckMasked,
                              CheckMask,
                              "cmp");

  //
  // Create the select instruction that, at run-time, will determine if we use
  // the bit-masked pointer or the original pointer value.
  //
  return (SelectInst::Create (Cmp, Masked, Pointer, "ptr", &I));
}

//
// Method: visitLoadInst()
//
// Description:
//  Place a run-time check on a load instruction.
//
void
SFI::visitLoadInst (LoadInst & LI) {
  //
  // Add the bit masking for the pointer.
  //
  Value * newPtr = addBitMasking (LI.getPointerOperand(), LI);

  //
  // Update the operand of the store so that it uses the bit-masked pointer.
  //
  LI.setOperand(0, newPtr);

  //
  // Update the statistics.
  //
  ++LSChecks;
  return;
}

//
// Method: visitStoreInst()
//
// Description:
//  Place a run-time check on a store instruction.
//
void
SFI::visitStoreInst (StoreInst & SI) {
  //
  // Add the bit masking for the pointer.
  //
  Value * newPtr = addBitMasking (SI.getPointerOperand(), SI);

  //
  // Update the operand of the store so that it uses the bit-masked pointer.
  //
  SI.setOperand(1, newPtr);

  //
  // Update the statistics.
  //
  ++LSChecks;
  return;
}

void
SFI::visitAtomicCmpXchgInst (AtomicCmpXchgInst & AI) {
#if 0
  //
  // If the check will always succeed, skip it.
  //
  if (isTriviallySafe (AI.getPointerOperand(), AI.getType()))
    return;

  //
  // Create a value representing the amount of memory, in bytes, that will be
  // modified.
  //
  TargetData & TD = getAnalysis<TargetData>();
  LLVMContext & Context = AI.getContext();
  uint64_t TypeSize=TD.getTypeStoreSize(AI.getType());
  IntegerType * IntType = IntegerType::getInt32Ty (Context);
  Value * AccessSize = ConstantInt::get (IntType, TypeSize);

  //
  // Create an STL container with the arguments.
  // The first argument is the pool handle (which is a NULL pointer).
  // The second argument is the pointer to check.
  //
  std::vector<Value *> args;
  args.push_back(ConstantPointerNull::get (getVoidPtrType(Context)));
  args.push_back(castTo (AI.getPointerOperand(), getVoidPtrType(Context), &AI));
  args.push_back (AccessSize);

  //
  // Create the call to the run-time check.  Place it *before* the compare and
  // exchange instruction.
  //
  CallInst * CI = CallInst::Create (PoolCheckUI, args, "", &AI);

  //
  // If there's debug information on the load instruction, add it to the
  // run-time check.
  //
  if (MDNode * MD = AI.getMetadata ("dbg"))
    CI->setMetadata ("dbg", MD);

  //
  // Update the statistics.
  //
  ++LSChecks;
#endif
  return;
}

void
SFI::visitAtomicRMWInst (AtomicRMWInst & AI) {
#if 0
  //
  // If the check will always succeed, skip it.
  //
  if (isTriviallySafe (AI.getPointerOperand(), AI.getType()))
    return;

  //
  // Create a value representing the amount of memory, in bytes, that will be
  // modified.
  //
  TargetData & TD = getAnalysis<TargetData>();
  LLVMContext & Context = AI.getContext();
  uint64_t TypeSize=TD.getTypeStoreSize(AI.getType());
  IntegerType * IntType = IntegerType::getInt32Ty (Context);
  Value * AccessSize = ConstantInt::get (IntType, TypeSize);

  //
  // Create an STL container with the arguments.
  // The first argument is the pool handle (which is a NULL pointer).
  // The second argument is the pointer to check.
  //
  std::vector<Value *> args;
  args.push_back(ConstantPointerNull::get (getVoidPtrType(Context)));
  args.push_back(castTo (AI.getPointerOperand(), getVoidPtrType(Context), &AI));
  args.push_back (AccessSize);

  //
  // Create the call to the run-time check.  Place it *before* the compare and
  // exchange instruction.
  //
  CallInst * CI = CallInst::Create (PoolCheckUI, args, "", &AI);

  //
  // If there's debug information on the load instruction, add it to the
  // run-time check.
  //
  if (MDNode * MD = AI.getMetadata ("dbg"))
    CI->setMetadata ("dbg", MD);

  //
  // Update the statistics.
  //
  ++LSChecks;
#endif
  return;
}

bool
SFI::runOnFunction (Function & F) {
  //
  // Visit all of the instructions in the function.
  //
  visit (F);
  return true;
}

}

namespace llvm {
  FunctionPass * createSFIPass (void) {
    return new SFI();
  }
}

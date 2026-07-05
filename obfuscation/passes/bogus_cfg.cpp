#include "llvm/Pass.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/CFG.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <cstdlib>
#include <ctime>
#include <vector>
#include <set>

using namespace llvm;

namespace {

struct BogusCFGPass : public PassInfoMixin<BogusCFGPass> {

    bool shouldObfuscate(Function &F) {
        if (F.empty()) return false;
        if (F.hasFnAttribute("no-bogus-cfg")) return false;
        StringRef Name = F.getName();
        if (Name.starts_with("llvm.")) return false;
        if (Name.starts_with("__ubsan")) return false;
        return true;
    }

    bool hasPHINodes(const BasicBlock &BB) {
        return isa<PHINode>(BB.front());
    }

    bool hasLandingPadOrEHPads(const BasicBlock &BB) {
        for (auto &I : BB) {
            if (isa<LandingPadInst>(I) || isa<CatchPadInst>(I) ||
                isa<CleanupPadInst>(I) || isa<CatchReturnInst>(I) ||
                isa<CleanupReturnInst>(I))
                return true;
            if (isa<ResumeInst>(I)) return true;
        }
        return false;
    }

    Value *createOpaqueTrueMBA(IRBuilder<> &B, LLVMContext &Ctx) {
        IntegerType *I32Ty = Type::getInt32Ty(Ctx);
        Value *A = B.CreateCall(Intrinsic::getDeclaration(
            B.GetInsertBlock()->getModule(), Intrinsic::readcyclecounter));
        A = B.CreateAnd(A, ConstantInt::get(I32Ty, 0xFFFF));
        Value *B_val = B.CreateXor(A, ConstantInt::get(I32Ty, 0xA5A5A5A5));
        Value *Xor1 = B.CreateXor(A, B_val);
        Value *And1 = B.CreateAnd(A, B_val);
        Value *Mul1 = B.CreateMul(And1, ConstantInt::get(I32Ty, 2));
        Value *LHS = B.CreateAdd(Xor1, Mul1);
        Value *RHS = B.CreateAdd(A, B_val);
        Value *CmpEq = B.CreateICmpEQ(LHS, RHS);
        Value *Xor2 = B.CreateXor(A, B_val);
        Value *Not1 = B.CreateNot(A);
        Value *Not2 = B.CreateNot(B_val);
        Value *And2 = B.CreateAnd(Not1, B_val);
        Value *And3 = B.CreateAnd(A, Not2);
        Value *Identity2 = B.CreateAdd(And2, And3);
        Value *CmpEq2 = B.CreateICmpEQ(Xor2, Identity2);
        return B.CreateAnd(CmpEq, CmpEq2);
    }

    Value *createOpaqueFalseMBA(IRBuilder<> &B, LLVMContext &Ctx) {
        IntegerType *I32Ty = Type::getInt32Ty(Ctx);
        Value *A = ConstantInt::get(I32Ty, opaqueInt());
        Value *B_val = ConstantInt::get(I32Ty, opaqueInt());

        Value *DivAB = B.CreateUDiv(A, B_val);
        Value *MulADiv = B.CreateMul(DivAB, B_val);
        Value *ModRem = B.CreateSub(A, MulADiv);
        Value *ModCheck = B.CreateICmpUGE(ModRem, B_val);
        return ModCheck;
    }

    static uint32_t opaqueInt() {
        static bool seeded = false;
        if (!seeded) { std::srand((unsigned)std::time(nullptr)); seeded = true; }
        return (uint32_t)std::rand();
    }

    void insertJunkInstructions(IRBuilder<> &B, LLVMContext &Ctx) {
        IntegerType *I32Ty = Type::getInt32Ty(Ctx);
        Value *J1 = ConstantInt::get(I32Ty, opaqueInt());
        Value *J2 = ConstantInt::get(I32Ty, opaqueInt());
        Value *J3 = B.CreateXor(J1, J2);
        Value *J4 = B.CreateAnd(J1, J2);
        Value *J5 = B.CreateAdd(J3, J4);
        (void)J5;
    }

    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
        if (!shouldObfuscate(F))
            return PreservedAnalyses::all();

        LLVMContext &Ctx = F.getContext();
        IntegerType *I32Ty = Type::getInt32Ty(Ctx);
        IntegerType *I1Ty = Type::getInt1Ty(Ctx);

        std::vector<BasicBlock *> OrigBlocks;
        for (auto &BB : F)
            OrigBlocks.push_back(&BB);

        if (OrigBlocks.size() < 2)
            return PreservedAnalyses::all();

        int numBogusBlocks = 2 + (std::rand() % 3);

        for (int i = 0; i < numBogusBlocks && OrigBlocks.size() > 1; ++i) {
            BasicBlock *TargetBB = OrigBlocks[std::rand() % OrigBlocks.size()];

            if (TargetBB == &F.getEntryBlock()) continue;
            if (hasLandingPadOrEHPads(*TargetBB)) continue;

            BasicBlock *BogusBB = BasicBlock::Create(Ctx, "bogus." + Twine(i), &F, TargetBB);
            BasicBlock *SinkBB = BasicBlock::Create(Ctx, "bogus.sink." + Twine(i), &F, TargetBB);

            IRBuilder<> B(BogusBB);
            insertJunkInstructions(B, Ctx);
            Value *FalsePred = createOpaqueFalseMBA(B, Ctx);
            B.CreateCondBr(FalsePred, SinkBB, TargetBB);

            IRBuilder<> S(SinkBB);
            insertJunkInstructions(S, Ctx);
            S.CreateBr(TargetBB);

            for (PHINode &PN : TargetBB->phis()) {
                unsigned numIncoming = PN.getNumIncomingValues();
                if (numIncoming > 0) {
                    Value *IncomingVal = PN.getIncomingValue(0);
                    PN.addIncoming(IncomingVal, BogusBB);
                    PN.addIncoming(IncomingVal, SinkBB);
                }
            }

            Instruction *Term = TargetBB->getTerminator();
            if (BranchInst *Br = dyn_cast<BranchInst>(Term)) {
                if (Br->isUnconditional()) {
                    BasicBlock *Succ = Br->getSuccessor(0);
                    if (Succ) {
                        for (PHINode &PN : Succ->phis()) {
                            for (unsigned j = 0; j < PN.getNumIncomingValues(); ++j) {
                                if (PN.getIncomingBlock(j) == TargetBB) {
                                    PN.addIncoming(PN.getIncomingValue(j), BogusBB);
                                    PN.addIncoming(PN.getIncomingValue(j), SinkBB);
                                }
                            }
                        }
                    }
                } else {
                    for (unsigned j = 0; j < 2; ++j) {
                        BasicBlock *Succ = Br->getSuccessor(j);
                        for (PHINode &PN : Succ->phis()) {
                            for (unsigned k = 0; k < PN.getNumIncomingValues(); ++k) {
                                if (PN.getIncomingBlock(k) == TargetBB) {
                                    PN.addIncoming(PN.getIncomingValue(k), BogusBB);
                                    PN.addIncoming(PN.getIncomingValue(k), SinkBB);
                                }
                            }
                        }
                    }
                }
            }
        }

        {
            BasicBlock &Entry = F.getEntryBlock();
            Instruction *FirstI = Entry.getFirstNonPHIOrDbg();
            if (FirstI && isa<AllocaInst>(FirstI)) {
                while (isa<AllocaInst>(FirstI->getNextNode()))
                    FirstI = FirstI->getNextNode();
                IRBuilder<> B(FirstI->getNextNode());
                insertJunkInstructions(B, Ctx);
            } else {
                IRBuilder<> B(&Entry, Entry.begin());
                insertJunkInstructions(B, Ctx);
            }
        }

        return PreservedAnalyses::none();
    }
};

} // anonymous namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        .APIVersion = LLVM_PLUGIN_API_VERSION,
        .PluginName = "bogus-cfg",
        .PluginVersion = "v0.1",
        .RegisterPassBuilderCallbacks = [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "bogus-cfg") {
                        FunctionPassManager FPM;
                        FPM.addPass(BogusCFGPass());
                        MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
                        return true;
                    }
                    return false;
                });
        }
    };
}

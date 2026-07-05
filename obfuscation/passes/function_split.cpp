#include "llvm/Pass.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/CFG.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cstdlib>
#include <ctime>

using namespace llvm;

namespace {

struct FunctionSplitPass : public PassInfoMixin<FunctionSplitPass> {

    bool shouldSplit(Function &F) {
        if (F.empty() || F.isDeclaration()) return false;
        if (F.hasFnAttribute("no-split")) return false;
        if (F.size() < 20) return false;
        StringRef Name = F.getName();
        if (Name.starts_with("llvm.")) return false;
        if (Name.starts_with("__ubsan")) return false;
        return true;
    }

    bool hasIndirectTerminators(Function &F) {
        for (auto &BB : F) {
            if (isa<IndirectBrInst>(BB.getTerminator())) return true;
            if (isa<LandingPadInst>(BB.front())) return true;
            if (isa<CatchPadInst>(BB.front()) || isa<CleanupPadInst>(BB.front())) return true;
            if (isa<CatchReturnInst>(BB.getTerminator()) || isa<CleanupReturnInst>(BB.getTerminator())) return true;
        }
        return false;
    }

    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
        std::srand((unsigned)std::time(nullptr));

        std::vector<Function *> Candidates;
        for (auto &F : M) {
            if (shouldSplit(F) && !hasIndirectTerminators(F))
                Candidates.push_back(&F);
        }

        if (Candidates.empty())
            return PreservedAnalyses::all();

        LLVMContext &Ctx = M.getContext();

        for (Function *F : Candidates) {
            unsigned totalBBs = 0;
            for (auto &BB : *F) { (void)BB; ++totalBBs; }

            unsigned chunkSize = std::max(4u, totalBBs / 3);
            if (chunkSize > 12) chunkSize = 12;

            std::vector<std::vector<BasicBlock *>> Chunks;
            std::vector<BasicBlock *> CurrentChunk;
            unsigned idx = 0;

            for (auto &BB : *F) {
                CurrentChunk.push_back(&BB);
                ++idx;
                if (CurrentChunk.size() >= chunkSize && idx < totalBBs) {
                    Chunks.push_back(CurrentChunk);
                    CurrentChunk.clear();
                }
            }
            if (!CurrentChunk.empty())
                Chunks.push_back(CurrentChunk);

            if (Chunks.size() < 2) continue;

            if (Chunks.size() > 1) {
                std::vector<std::vector<BasicBlock *>> Shuffled(Chunks.begin() + 1, Chunks.end());
                std::random_shuffle(Shuffled.begin(), Shuffled.end());
                for (size_t i = 0; i < Shuffled.size(); ++i)
                    Chunks[i + 1] = Shuffled[i];
            }

            std::vector<Function *> SubFuncs;
            Function *MainFunc = F;

            for (size_t c = 0; c < Chunks.size(); ++c) {
                if (c == 0) continue;

                auto &Blocks = Chunks[c];
                std::string SubName = F->getName().str() + ".split." + Twine(c).str();
                FunctionType *FT = F->getFunctionType();
                Function *SubF = Function::Create(FT, Function::InternalLinkage, SubName, &M);

                BasicBlock *SubEntry = BasicBlock::Create(Ctx, "sub.entry", SubF);
                IRBuilder<> EB(SubEntry);

                std::vector<Value *> Args;
                for (auto &Arg : SubF->args()) {
                    Args.push_back(&Arg);
                }
                EB.CreateRetVoid();

                std::map<const BasicBlock *, BasicBlock *> BlockMap;
                for (BasicBlock *BB : Blocks) {
                    BasicBlock *NewBB = BasicBlock::Create(Ctx, BB->getName() + ".sub", SubF);
                    BlockMap[BB] = NewBB;
                }

                ValueToValueMapTy VMap;
                for (BasicBlock *BB : Blocks) {
                    BasicBlock *NewBB = BlockMap[BB];
                    for (auto &I : *BB) {
                        Instruction *NewI = I.clone();
                        NewBB->getInstList().push_back(NewI);
                        VMap[&I] = NewI;
                    }
                }

                for (auto &BB : *SubF) {
                    for (auto &I : BB) {
                        RemapInstruction(&I, VMap,
                            RF_NoModuleLevelChanges | RF_IgnoreMissingLocals);
                    }
                }

                Function *OwningF = const_cast<Function *>(Blocks[0]->getParent());
                for (BasicBlock *BB : Blocks) {
                    BB->removeFromParent();
                }

                for (BasicBlock *BB : Blocks) {
                    BasicBlock *NewBB = BlockMap[BB];
                    for (auto &I : *NewBB) {
                        if (ReturnInst *RI = dyn_cast<ReturnInst>(&I)) {
                        } else if (BranchInst *Br = dyn_cast<BranchInst>(&I)) {
                            for (unsigned j = 0; j < Br->getNumSuccessors(); ++j) {
                                BasicBlock *Target = Br->getSuccessor(j);
                                if (BlockMap.count(Target)) {
                                    Br->setSuccessor(j, BlockMap[Target]);
                                }
                            }
                        }
                    }
                }

                SubFuncs.push_back(SubF);
            }

            for (size_t c = 1; c < Chunks.size(); ++c) {
                Function *SubF = SubFuncs[c - 1];
                if (!SubF) continue;

                BasicBlock *FirstBB = &SubF->front();
                Instruction *Term = FirstBB->getTerminator();
                if (Term) Term->eraseFromParent();

                auto &OrigBlocks = Chunks[c];
                BasicBlock *OriginalFirst = nullptr;
                for (BasicBlock &BB : *F) {
                    OriginalFirst = &BB;
                    break;
                }

                IRBuilder<> B(FirstBB);
                if (OriginalFirst) {
                    std::vector<Value *> CallArgs;
                    for (auto &Arg : SubF->args()) {
                        CallArgs.push_back(&Arg);
                    }
                    CallInst *CI = B.CreateCall(F->getFunctionType(), MainFunc, CallArgs);
                    if (!F->getReturnType()->isVoidTy()) {
                        B.CreateRet(CI);
                    } else {
                        B.CreateRetVoid();
                    }
                }

                BasicBlock *TrampolineBB = BasicBlock::Create(Ctx, "trampoline." + Twine(c), F);
                IRBuilder<> TB(TrampolineBB);
                std::vector<Value *> TrampolineArgs;
                for (auto &Arg : F->args()) {
                    TrampolineArgs.push_back(&Arg);
                }
                CallInst *TrampCI = TB.CreateCall(SubF, TrampolineArgs);
                if (!F->getReturnType()->isVoidTy()) {
                    TB.CreateRet(TrampCI);
                } else {
                    TB.CreateRetVoid();
                }

                if (OriginalFirst) {
                    TrampolineBB->moveBefore(OriginalFirst);
                }
            }
        }

        return PreservedAnalyses::none();
    }
};

} // anonymous namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        .APIVersion = LLVM_PLUGIN_API_VERSION,
        .PluginName = "function-split",
        .PluginVersion = "v0.1",
        .RegisterPassBuilderCallbacks = [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "function-split") {
                        MPM.addPass(FunctionSplitPass());
                        return true;
                    }
                    return false;
                });
        }
    };
}

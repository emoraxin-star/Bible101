#include "llvm/Pass.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <vector>
#include <map>
#include <cstdlib>
#include <ctime>

using namespace llvm;

namespace {

static uint32_t opaqueInt() {
    static bool seeded = false;
    if (!seeded) { std::srand((unsigned)std::time(nullptr)); seeded = true; }
    return (uint32_t)std::rand();
}

struct CFGFlattenPass : public PassInfoMixin<CFGFlattenPass> {

    bool shouldFlatten(Function &F) {
        if (F.size() < 4) return false;
        if (F.hasFnAttribute("no-flatten")) return false;
        StringRef Name = F.getName();
        if (Name.starts_with("llvm.")) return false;
        if (Name.starts_with("__ubsan")) return false;
        return true;
    }

    Value *createOpaqueTrue(IRBuilder<> &B, Function &F) {
        IntegerType *I32Ty = Type::getInt32Ty(F.getContext());
        Value *A = ConstantInt::get(I32Ty, opaqueInt());
        Value *B = ConstantInt::get(I32Ty, opaqueInt());
        Value *Xor = B.CreateXor(A, B);
        Value *And = B.CreateAnd(A, B);
        Value *Mul = B.CreateMul(And, ConstantInt::get(I32Ty, 2));
        Value *LHS = B.CreateAdd(Xor, Mul);
        Value *RHS = B.CreateAdd(A, B);
        return B.CreateICmpEQ(LHS, RHS);
    }

    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
        if (!shouldFlatten(F))
            return PreservedAnalyses::all();

        LLVMContext &Ctx = F.getContext();
        IntegerType *I32Ty = Type::getInt32Ty(Ctx);

        if (F.hasFnAttribute("flatten-threshold")) {
            Attribute Attr = F.getFnAttribute("flatten-threshold");
            int threshold;
            if (!Attr.getValueAsString().getAsInteger(10, threshold)) {
                int bbCount = 0;
                for (auto &BB : F) { (void)BB; ++bbCount; }
                if (bbCount < threshold)
                    return PreservedAnalyses::all();
            }
        }

        for (auto &BB : F) {
            if (isa<IndirectBrInst>(BB.getTerminator()))
                return PreservedAnalyses::all();
            if (isa<LandingPadInst>(BB.front()))
                return PreservedAnalyses::all();
            if (isa<CatchPadInst>(BB.front()) || isa<CleanupPadInst>(BB.front()))
                return PreservedAnalyses::all();
        }

        std::vector<BasicBlock *> OrigBlocks;
        for (auto &BB : F)
            OrigBlocks.push_back(&BB);

        if (OrigBlocks.size() < 3)
            return PreservedAnalyses::all();

        BasicBlock &EntryBB = F.getEntryBlock();
        BasicBlock *SwitchBB = BasicBlock::Create(Ctx, "flatten.switch", &F);
        BasicBlock *PreHeaderBB = BasicBlock::Create(Ctx, "flatten.preheader", &F);
        BasicBlock *EndBB = BasicBlock::Create(Ctx, "flatten.end", &F);

        AllocaInst *StateVar = new AllocaInst(I32Ty, 0, "flatten.state", &F.front().front());
        IRBuilder<> PB(PreHeaderBB);
        PB.CreateStore(ConstantInt::get(I32Ty, 1), StateVar);
        PB.CreateBr(SwitchBB);

        IRBuilder<> SB(SwitchBB);
        LoadInst *State = SB.CreateLoad(I32Ty, StateVar, "flatten.state.load");

        unsigned numCases = OrigBlocks.size();
        SwitchInst *Switch = SB.CreateSwitch(State, EndBB, numCases);

        std::map<BasicBlock *, unsigned> BlockToCase;
        for (unsigned i = 0; i < OrigBlocks.size(); ++i)
            BlockToCase[OrigBlocks[i]] = i + 1;

        Function *Parent = &F;
        for (BasicBlock *BB : OrigBlocks) {
            BB->moveAfter(SwitchBB);
            Switch->addCase(ConstantInt::get(I32Ty, BlockToCase[BB]), BB);

            Instruction *Term = BB->getTerminator();

            if (BranchInst *Br = dyn_cast<BranchInst>(Term)) {
                if (Br->isUnconditional()) {
                    BasicBlock *Target = Br->getSuccessor(0);
                    unsigned nextCase = BlockToCase[Target];
                    IRBuilder<> B(Br);
                    B.CreateStore(ConstantInt::get(I32Ty, nextCase), StateVar);
                    B.CreateBr(SwitchBB);
                    Br->eraseFromParent();
                } else {
                    BasicBlock *TrueTarget = Br->getSuccessor(0);
                    BasicBlock *FalseTarget = Br->getSuccessor(1);
                    unsigned trueCase = BlockToCase[TrueTarget];
                    unsigned falseCase = BlockToCase[FalseTarget];

                    IRBuilder<> B(Br);
                    Value *OpaquePred = createOpaqueTrue(B, F);
                    Value *FinalPred = B.CreateAnd(Br->getCondition(), OpaquePred);

                    unsigned nextCase = BlockToCase[Br->getSuccessor(0)];
                    B.CreateStore(ConstantInt::get(I32Ty, nextCase), StateVar);
                    B.CreateBr(SwitchBB);
                    Br->eraseFromParent();
                }
            } else if (SwitchInst *Sw = dyn_cast<SwitchInst>(Term)) {
                unsigned defaultCase = BlockToCase[Sw->getDefaultDest()];
                IRBuilder<> B(Term);
                B.CreateStore(ConstantInt::get(I32Ty, defaultCase), StateVar);
                B.CreateBr(SwitchBB);
                Term->eraseFromParent();
            } else if (isa<ReturnInst>(Term) || isa<ResumeInst>(Term)) {
            } else if (isa<UnreachableInst>(Term)) {
            } else {
                return PreservedAnalyses::all();
            }
        }

        PreHeaderBB->moveBefore(SwitchBB);
        SwitchBB->moveAfter(PreHeaderBB);

        if (!EntryBB.empty() && isa<AllocaInst>(*EntryBB.begin())) {
            EntryBB.moveBefore(PreHeaderBB);
        } else {
            BasicBlock *NewEntry = BasicBlock::Create(Ctx, "flatten.entry", &F, PreHeaderBB);
            IRBuilder<> EB(NewEntry);
            EB.CreateBr(PreHeaderBB);
        }

        return PreservedAnalyses::none();
    }
};

} // anonymous namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        .APIVersion = LLVM_PLUGIN_API_VERSION,
        .PluginName = "cfg-flatten",
        .PluginVersion = "v0.1",
        .RegisterPassBuilderCallbacks = [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "cfg-flatten") {
                        FunctionPassManager FPM;
                        FPM.addPass(CFGFlattenPass());
                        MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
                        return true;
                    }
                    return false;
                });
        }
    };
}

#include "llvm/Pass.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Format.h"
#include <cstdlib>
#include <ctime>
#include <map>
#include <vector>

using namespace llvm;

namespace {

static uint8_t g_KeyPool[256];
static bool g_KeyPoolInitialized = false;

static void initKeyPool() {
    if (g_KeyPoolInitialized) return;
    std::srand((unsigned)std::time(nullptr));
    for (int i = 0; i < 256; ++i)
        g_KeyPool[i] = (uint8_t)(std::rand() & 0xFF);
    g_KeyPoolInitialized = true;
}

static uint8_t randomByte() {
    initKeyPool();
    return g_KeyPool[std::rand() % 256];
}

static uint32_t functionHash(const Function &F) {
    uint32_t h = 0x811C9DC5u;
    StringRef name = F.getName();
    for (char c : name) {
        h ^= (uint8_t)c;
        h *= 0x01000193u;
    }
    return h;
}

struct StringEncryptPass : public PassInfoMixin<StringEncryptPass> {

    struct EncryptedString {
        GlobalVariable *OrigGV;
        std::vector<uint8_t> EncryptedData;
        uint8_t Key;
        uint32_t KeyXorHash;
    };

    std::vector<EncryptedString> EncryptedStrings;

    bool isStringGlobal(GlobalVariable *GV) {
        if (!GV->hasInitializer()) return false;
        if (!GV->isConstant()) return false;
        ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(GV->getInitializer());
        if (!CDS || !CDS->isString()) return false;
        if (CDS->getNumElements() < 2) return false;
        return true;
    }

    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
        initKeyPool();
        std::srand((unsigned)std::time(nullptr));

        LLVMContext &Ctx = M.getContext();
        std::vector<GlobalVariable *> Strings;

        for (GlobalVariable &GV : M.globals()) {
            if (isStringGlobal(&GV))
                Strings.push_back(&GV);
        }

        if (Strings.empty())
            return PreservedAnalyses::all();

        IntegerType *Int8Ty = Type::getInt8Ty(Ctx);
        IntegerType *Int32Ty = Type::getInt32Ty(Ctx);

        for (GlobalVariable *GV : Strings) {
            ConstantDataSequential *CDS = cast<ConstantDataSequential>(GV->getInitializer());
            StringRef Str = CDS->getRawDataValues();
            if (Str.empty()) continue;

            uint8_t key = randomByte();
            std::vector<uint8_t> encrypted(Str.size());
            for (size_t i = 0; i < Str.size(); ++i)
                encrypted[i] = (uint8_t)Str[i] ^ key;

            Constant *EncConst = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(encrypted));

            GV->setInitializer(EncConst);
            GV->setConstant(false);

            EncryptedStrings.push_back({GV, encrypted, key, 0});
        }

        for (Function &F : M) {
            if (F.isDeclaration() || F.empty()) continue;
            uint32_t fHash = functionHash(F);

            for (auto &ES : EncryptedStrings) {
                ES.KeyXorHash = (uint32_t)ES.Key ^ fHash;
            }

            insertDecryptStubs(F, EncryptedStrings);
        }

        return PreservedAnalyses::none();
    }

    void insertDecryptStubAt(IRBuilder<> &B, Value *StrPtr, uint64_t Length, uint8_t Key, uint32_t KeyXorHash, uint32_t FnHash) {
        LLVMContext &Ctx = B.getContext();
        IntegerType *Int8Ty = Type::getInt8Ty(Ctx);
        IntegerType *Int32Ty = Type::getInt32Ty(Ctx);
        PointerType *Int8PtrTy = PointerType::getUnqual(Ctx);

        uint8_t recoveredKey = (uint8_t)(KeyXorHash ^ FnHash);

        if (recoveredKey == 0) return;

        Value *Ptr = B.CreateBitCast(StrPtr, Int8PtrTy);
        Constant *KeyConst = ConstantInt::get(Int8Ty, recoveredKey);
        Constant *Zero = ConstantInt::get(Int8Ty, 0);

        for (uint64_t i = 0; i < Length; ++i) {
            Value *GEP = B.CreateGEP(Int8Ty, Ptr, ConstantInt::get(Int32Ty, i));
            Value *Loaded = B.CreateLoad(Int8Ty, GEP);
            Value *Decrypted = B.CreateXor(Loaded, KeyConst);
            B.CreateStore(Decrypted, GEP);
        }
    }

    void insertDecryptStubs(Function &F, std::vector<EncryptedString> &Strings) {
        uint32_t fHash = functionHash(F);

        for (auto &BB : F) {
            for (auto &I : BB) {
                for (unsigned opIdx = 0; opIdx < I.getNumOperands(); ++opIdx) {
                    Value *Op = I.getOperand(opIdx);
                    GlobalVariable *GV = dyn_cast<GlobalVariable>(Op);
                    if (!GV) continue;

                    for (auto &ES : Strings) {
                        if (ES.OrigGV != GV) continue;

                        IRBuilder<> B(&I);
                        uint32_t effectiveKeyXor = ES.KeyXorHash;
                        if (effectiveKeyXor == 0)
                            effectiveKeyXor = (uint32_t)ES.Key ^ fHash;

                        insertDecryptStubAt(B, GV, ES.EncryptedData.size(),
                                            ES.Key, effectiveKeyXor, fHash);
                    }
                }
            }
        }
    }
};

} // anonymous namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        .APIVersion = LLVM_PLUGIN_API_VERSION,
        .PluginName = "string-encrypt",
        .PluginVersion = "v0.1",
        .RegisterPassBuilderCallbacks = [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "string-encrypt") {
                        MPM.addPass(StringEncryptPass());
                        return true;
                    }
                    return false;
                });
            PB.registerParsePipelineCallback([&](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                return false;
            });
        }
    };
}

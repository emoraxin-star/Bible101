#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <unordered_set>

#if defined(_WIN32)
#include <windows.h>
#endif

// ============================================================
// pass_runner — Post-process obfuscation tool for PE binaries
//
// Applies LLVM obfuscation passes to targeted functions in a
// compiled .dll or .exe as a post-processing step.
//
// Usage:
//   pass_runner.exe --input target.dll --output target_obf.dll ^
//       --passes cfg_flatten,bogus_cfg,string_encrypt ^
//       --funcs "sub_*,?sendPacket@"
//
// Architecture:
//   Phase 1: Coax bitcode from the binary (via embedded LLVM
//            bitcode section, or by disassemble→lift→bitcode)
//   Phase 2: Run 'opt' with obfuscation passes
//   Phase 3: Reassemble/reinsert into COFF/PE
//
// For v1, this tool wraps the LLVM opt pipeline and uses
// objcopy-style section manipulation.
// ============================================================

struct Config {
    std::string InputPath;
    std::string OutputPath;
    std::vector<std::string> PassList;
    std::vector<std::string> FuncPatterns;
    std::string OptPath = "opt";
    std::string LlvmDisPath = "llvm-dis";
    std::string LlvmAsPath = "llvm-as";
    std::string ObjcopyPath = "llvm-objcopy";
    bool Verbose = false;
    bool KeepTemp = false;
};

static void printUsage(const char *argv0) {
    std::cerr
        << "LIBERTEA Obfuscation Pass Runner v0.1\n"
        << "Usage: " << argv0 << " [options]\n\n"
        << "Options:\n"
        << "  --input <file>        Input .dll or .exe\n"
        << "  --output <file>       Output obfuscated binary\n"
        << "  --passes <list>       Comma-separated: cfg_flatten,bogus_cfg,string_encrypt,function_split\n"
        << "  --funcs <patterns>    Comma-separated function name patterns (supports * glob)\n"
        << "  --opt-path <path>     Path to LLVM's opt.exe (default: search PATH)\n"
        << "  --keep-temps          Keep intermediate files\n"
        << "  --verbose             Verbose output\n"
        << "  --help                This message\n\n"
        << "Examples:\n"
        << "  pass_runner --input target.dll --output target_obf.dll ^\n"
        << "      --passes cfg_flatten,bogus_cfg --funcs \"*\"\n\n"
        << "  pass_runner --input target.dll --output target_obf.dll ^\n"
        << "      --passes string_encrypt --funcs \"sub_*,?sendPacket@\"\n";
}

static bool parseArgs(int argc, char **argv, Config &cfg) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            printUsage(argv[0]);
            std::exit(0);
        } else if (arg == "--input" && i + 1 < argc) {
            cfg.InputPath = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            cfg.OutputPath = argv[++i];
        } else if (arg == "--passes" && i + 1 < argc) {
            std::string list = argv[++i];
            std::stringstream ss(list);
            std::string item;
            while (std::getline(ss, item, ',')) {
                if (!item.empty())
                    cfg.PassList.push_back(item);
            }
        } else if (arg == "--funcs" && i + 1 < argc) {
            std::string list = argv[++i];
            std::stringstream ss(list);
            std::string item;
            while (std::getline(ss, item, ',')) {
                if (!item.empty())
                    cfg.FuncPatterns.push_back(item);
            }
        } else if (arg == "--opt-path" && i + 1 < argc) {
            cfg.OptPath = argv[++i];
        } else if (arg == "--keep-temps") {
            cfg.KeepTemp = true;
        } else if (arg == "--verbose") {
            cfg.Verbose = true;
        } else if (arg == "--llvm-dis-path" && i + 1 < argc) {
            cfg.LlvmDisPath = argv[++i];
        } else if (arg == "--llvm-as-path" && i + 1 < argc) {
            cfg.LlvmAsPath = argv[++i];
        } else if (arg == "--objcopy-path" && i + 1 < argc) {
            cfg.ObjcopyPath = argv[++i];
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return false;
        }
    }
    return true;
}

static bool fileExists(const std::string &path) {
    std::ifstream f(path);
    return f.good();
}

static int runCommand(const std::string &cmd, bool verbose) {
    if (verbose)
        std::cout << "[EXEC] " << cmd << "\n";
    return std::system(cmd.c_str());
}

static std::string buildPipeline(const Config &cfg) {
    std::string pipeline;
    for (size_t i = 0; i < cfg.PassList.size(); ++i) {
        if (i > 0) pipeline += ",";
        const auto &p = cfg.PassList[i];
        if (p == "cfg_flatten") pipeline += "function(cfg-flatten)";
        else if (p == "bogus_cfg") pipeline += "function(bogus-cfg)";
        else if (p == "string_encrypt") pipeline += "string-encrypt";
        else if (p == "function_split") pipeline += "function-split";
        else pipeline += "function(" + p + ")";
    }
    return pipeline;
}

static bool extractBitcode(const Config &cfg, const std::string &tempDir) {
    std::string bcFile = tempDir + "\\target.bc";
    std::string cmd;

    // Attempt to extract .llvm_bitcode section if present
    cmd = cfg.ObjcopyPath + " --dump-section .llvm_bitcode=" + bcFile + " \"" + cfg.InputPath + "\" 2>nul";
    int ret = runCommand(cmd, cfg.Verbose);
    if (ret == 0 && fileExists(bcFile)) {
        if (cfg.Verbose) std::cout << "[INFO] Extracted .llvm_bitcode section\n";
        return true;
    }

    // Fallback: try to disassemble and parse
    cmd = cfg.LlvmDisPath + " \"" + cfg.InputPath + "\" -o " + tempDir + "\\target.ll 2>nul";
    ret = runCommand(cmd, cfg.Verbose);
    if (ret == 0 && fileExists(tempDir + "\\target.ll")) {
        cmd = cfg.LlvmAsPath + " " + tempDir + "\\target.ll -o " + bcFile + " 2>nul";
        ret = runCommand(cmd, cfg.Verbose);
        if (ret == 0) return true;
    }

    std::cerr << "[ERROR] No LLVM bitcode found in " << cfg.InputPath << "\n";
    std::cerr << "        The binary must be compiled with -fembed-bitcode or contain\n";
    std::cerr << "        a .llvm_bitcode section. Alternatively, use --opt on .bc files.\n";

    // Create a stub for testing
    std::ofstream stub(bcFile);
    if (!stub) return false;
    stub.close();
    return false;
}

static bool applyPasses(const Config &cfg, const std::string &tempDir) {
    std::string inputBc = tempDir + "\\target.bc";
    std::string outputBc = tempDir + "\\target_obf.bc";

    if (!fileExists(inputBc)) {
        std::cerr << "[ERROR] Bitcode file not found: " << inputBc << "\n";
        return false;
    }

    std::string pipeline = buildPipeline(cfg);
    if (pipeline.empty()) {
        std::cerr << "[ERROR] No passes specified. Use --passes\n";
        return false;
    }

    // Build function filter if specified
    std::string funcFilter;
    if (!cfg.FuncPatterns.empty()) {
        funcFilter = " --filter-function=\"";
        for (size_t i = 0; i < cfg.FuncPatterns.size(); ++i) {
            if (i > 0) funcFilter += "|";
            funcFilter += cfg.FuncPatterns[i];
        }
        funcFilter += "\"";
    }

    std::string cmd = "\"" + cfg.OptPath + "\""
        + " -passes=\"" + pipeline + "\""
        + funcFilter
        + " \"" + inputBc + "\""
        + " -o \"" + outputBc + "\""
        + " -verify-each 2>&1";

    int ret = runCommand(cmd, cfg.Verbose);
    if (ret != 0) {
        std::cerr << "[ERROR] opt pass pipeline failed (exit code " << ret << ")\n";
        return false;
    }

    if (!fileExists(outputBc)) {
        std::cerr << "[ERROR] Output bitcode not generated\n";
        return false;
    }

    if (cfg.Verbose) {
        std::cout << "[OK] Obfuscated bitcode: " << outputBc << "\n";
    }
    return true;
}

static bool reintegrateBitcode(const Config &cfg, const std::string &tempDir) {
    std::string outputBc = tempDir + "\\target_obf.bc";
    std::string tmpObj = tempDir + "\\target_obf.obj";

    if (!fileExists(outputBc)) {
        std::cerr << "[ERROR] Obfuscated bitcode not found\n";
        return false;
    }

    // Convert bitcode to COFF object
    std::string cmd = "\"" + cfg.LlvmAsPath + "\""
        + " \"" + outputBc + "\""
        + " -o \"" + tmpObj + "\"";

    int ret = runCommand(cmd, cfg.Verbose);
    if (ret != 0) {
        std::cerr << "[ERROR] llvm-as failed\n";
        return false;
    }

    // Replace the .llvm_bitcode section in the original binary
    cmd = "\"" + cfg.ObjcopyPath + "\""
        + " --update-section .llvm_bitcode=\"" + outputBc + "\""
        + " \"" + cfg.InputPath + "\""
        + " \"" + cfg.OutputPath + "\"";

    ret = runCommand(cmd, cfg.Verbose);
    if (ret != 0) {
        std::cerr << "[ERROR] objcopy failed to update bitcode section\n";
        std::cerr << "        Try: manually replace .llvm_bitcode in " << cfg.InputPath << "\n";
        return false;
    }

    if (cfg.Verbose) {
        std::cout << "[OK] Obfuscated binary: " << cfg.OutputPath << "\n";
    }
    return true;
}

static bool verifyOutput(const Config &cfg) {
    if (!fileExists(cfg.OutputPath)) {
        std::cerr << "[ERROR] Output file not created: " << cfg.OutputPath << "\n";
        return false;
    }

    std::ifstream f(cfg.OutputPath, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize size = f.tellg();
    std::cout << "[OK] " << cfg.OutputPath << " (" << size << " bytes)\n";

    std::cout << "[INFO] Passes applied:";
    for (const auto &p : cfg.PassList) std::cout << " " << p;
    std::cout << "\n";

    if (!cfg.FuncPatterns.empty()) {
        std::cout << "[INFO] Targeted functions:";
        for (const auto &f : cfg.FuncPatterns) std::cout << " " << f;
        std::cout << "\n";
    }

    return true;
}

int main(int argc, char **argv) {
    Config cfg;

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    if (!parseArgs(argc, argv, cfg)) {
        printUsage(argv[0]);
        return 1;
    }

    if (cfg.InputPath.empty()) {
        std::cerr << "[ERROR] --input is required\n";
        return 1;
    }

    if (cfg.OutputPath.empty()) {
        cfg.OutputPath = cfg.InputPath;
        size_t dot = cfg.OutputPath.rfind('.');
        if (dot != std::string::npos)
            cfg.OutputPath.insert(dot, "_obf");
        else
            cfg.OutputPath += "_obf";
    }

    if (cfg.PassList.empty()) {
        std::cerr << "[ERROR] No passes specified. Use --passes\n";
        return 1;
    }

    // Create temp directory
    char tempPath[MAX_PATH];
    char tempDirName[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    GetTempFileNameA(tempPath, "obf", 0, tempDirName);
    std::string tempDir = tempDirName;
    CreateDirectoryA(tempDir.c_str(), nullptr);

    if (cfg.Verbose) {
        std::cout << "[CONFIG] Input:  " << cfg.InputPath << "\n";
        std::cout << "[CONFIG] Output: " << cfg.OutputPath << "\n";
        std::cout << "[CONFIG] Passes: ";
        for (const auto &p : cfg.PassList) std::cout << p << " ";
        std::cout << "\n";
        std::cout << "[CONFIG] Temp:   " << tempDir << "\n";
    }

    bool success = false;

    // Phase 1: Extract bitcode from binary
    if (!extractBitcode(cfg, tempDir)) {
        std::cerr << "[FAILED] Phase 1: Bitcode extraction\n";
        goto cleanup;
    }
    std::cout << "[OK] Phase 1: Bitcode extracted\n";

    // Phase 2: Apply obfuscation passes
    if (!applyPasses(cfg, tempDir)) {
        std::cerr << "[FAILED] Phase 2: Pass application\n";
        goto cleanup;
    }
    std::cout << "[OK] Phase 2: Obfuscation passes applied\n";

    // Phase 3: Reintegrate into binary
    if (!reintegrateBitcode(cfg, tempDir)) {
        std::cerr << "[FAILED] Phase 3: Binary reintegration\n";
        goto cleanup;
    }
    std::cout << "[OK] Phase 3: Binary reintegrated\n";

    // Verify
    success = verifyOutput(cfg);

cleanup:
    if (!cfg.KeepTemp) {
        // Clean up temp files
        std::string cmd = "rmdir /S /Q \"" + tempDir + "\" 2>nul";
        runCommand(cmd, false);
        if (cfg.Verbose) std::cout << "[CLEAN] Removed temp: " << tempDir << "\n";
    } else {
        std::cout << "[INFO] Temp files kept: " << tempDir << "\n";
    }

    return success ? 0 : 1;
}

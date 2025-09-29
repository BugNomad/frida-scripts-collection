/**
 * Native 层函数导出脚本
 * 导出 SO 库的函数符号、内存布局等信息
 */

console.log("[Native Dump] 开始 Native 层分析...");

const outputDir = "/data/local/tmp/native_dump";
const targetLibs = ["libnative-lib.so", "libssl.so", "libcrypto.so", "libc.so"];

// 创建输出目录
const fs = require('fs');
try {
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
        console.log("[Native Dump] 创建输出目录: " + outputDir);
    }
} catch (e) {
    console.log("[Native Dump] 创建目录失败: " + e);
}

// 获取所有已加载的模块
function dumpLoadedModules() {
    console.log("[Native Dump] 扫描已加载的模块...");
    
    const modules = Process.enumerateModules();
    const moduleInfo = [];
    
    modules.forEach(function(module) {
        const info = {
            name: module.name,
            base: module.base,
            size: module.size,
            path: module.path
        };
        
        moduleInfo.push(info);
        console.log("[Native Dump] 模块: " + module.name + " @ " + module.base + " (大小: " + module.size + ")");
        
        // 如果是目标库，进行详细分析
        if (isTargetLib(module.name)) {
            dumpModuleDetails(module);
        }
    });
    
    // 保存模块信息
    const timestamp = new Date().getTime();
    const outputPath = outputDir + "/" + timestamp + "_modules.json";
    
    try {
        fs.writeFileSync(outputPath, JSON.stringify(moduleInfo, null, 2));
        console.log("[Native Dump] 模块信息已保存: " + outputPath);
    } catch (e) {
        console.log("[Native Dump] 保存模块信息失败: " + e);
    }
}

// 检查是否为目标库
function isTargetLib(libName) {
    return targetLibs.some(target => libName.includes(target));
}

// 导出模块详细信息
function dumpModuleDetails(module) {
    console.log("[Native Dump] 分析模块: " + module.name);
    
    const details = {
        name: module.name,
        base: module.base,
        size: module.size,
        path: module.path,
        exports: [],
        imports: [],
        symbols: []
    };
    
    // 导出函数
    try {
        const exports = module.enumerateExports();
        exports.forEach(function(exp) {
            details.exports.push({
                name: exp.name,
                address: exp.address,
                type: exp.type
            });
        });
        console.log("[Native Dump] 找到 " + exports.length + " 个导出函数");
    } catch (e) {
        console.log("[Native Dump] 获取导出函数失败: " + e);
    }
    
    // 导入函数
    try {
        const imports = module.enumerateImports();
        imports.forEach(function(imp) {
            details.imports.push({
                name: imp.name,
                address: imp.address,
                module: imp.module,
                slot: imp.slot
            });
        });
        console.log("[Native Dump] 找到 " + imports.length + " 个导入函数");
    } catch (e) {
        console.log("[Native Dump] 获取导入函数失败: " + e);
    }
    
    // 符号信息
    try {
        const symbols = module.enumerateSymbols();
        symbols.forEach(function(sym) {
            details.symbols.push({
                name: sym.name,
                address: sym.address,
                type: sym.type,
                section: sym.section
            });
        });
        console.log("[Native Dump] 找到 " + symbols.length + " 个符号");
    } catch (e) {
        console.log("[Native Dump] 获取符号失败: " + e);
    }
    
    // 保存详细信息
    const timestamp = new Date().getTime();
    const safeName = module.name.replace(/[^a-zA-Z0-9]/g, '_');
    const outputPath = outputDir + "/" + timestamp + "_" + safeName + "_details.json";
    
    try {
        fs.writeFileSync(outputPath, JSON.stringify(details, null, 2));
        console.log("[Native Dump] 模块详情已保存: " + outputPath);
    } catch (e) {
        console.log("[Native Dump] 保存模块详情失败: " + e);
    }
    
    // 导出内存内容
    dumpModuleMemory(module);
}

// 导出模块内存
function dumpModuleMemory(module) {
    try {
        console.log("[Native Dump] 导出模块内存: " + module.name);
        
        const memory = Memory.readByteArray(module.base, Math.min(module.size, 1024 * 1024)); // 最多 1MB
        const timestamp = new Date().getTime();
        const safeName = module.name.replace(/[^a-zA-Z0-9]/g, '_');
        const outputPath = outputDir + "/" + timestamp + "_" + safeName + "_memory.bin";
        
        fs.writeFileSync(outputPath, Buffer.from(memory));
        console.log("[Native Dump] 内存已导出: " + outputPath);
        
    } catch (e) {
        console.log("[Native Dump] 导出内存失败: " + e);
    }
}

// Hook dlopen 来监控动态加载的库
function hookDlopen() {
    const dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function(args) {
                const path = Memory.readUtf8String(args[0]);
                console.log("[Native Dump] dlopen 调用: " + path);
                this.path = path;
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0 && this.path) {
                    console.log("[Native Dump] 库加载成功: " + this.path);
                    
                    // 延迟分析新加载的库
                    setTimeout(function() {
                        const modules = Process.enumerateModules();
                        modules.forEach(function(module) {
                            if (module.path === this.path && isTargetLib(module.name)) {
                                dumpModuleDetails(module);
                            }
                        });
                    }.bind(this), 1000);
                }
            }
        });
        console.log("[Native Dump] 已 Hook dlopen");
    }
}

// Hook android_dlopen_ext (Android 特有)
function hookAndroidDlopen() {
    const android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function(args) {
                const path = Memory.readUtf8String(args[0]);
                console.log("[Native Dump] android_dlopen_ext 调用: " + path);
                this.path = path;
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0 && this.path) {
                    console.log("[Native Dump] Android 库加载成功: " + this.path);
                }
            }
        });
        console.log("[Native Dump] 已 Hook android_dlopen_ext");
    }
}

// 搜索特定函数
function searchFunctions(patterns) {
    console.log("[Native Dump] 搜索函数模式...");
    
    const results = [];
    const modules = Process.enumerateModules();
    
    modules.forEach(function(module) {
        if (isTargetLib(module.name)) {
            try {
                const exports = module.enumerateExports();
                exports.forEach(function(exp) {
                    patterns.forEach(function(pattern) {
                        if (exp.name.includes(pattern)) {
                            results.push({
                                module: module.name,
                                function: exp.name,
                                address: exp.address,
                                pattern: pattern
                            });
                            console.log("[Native Dump] 找到匹配函数: " + module.name + "!" + exp.name);
                        }
                    });
                });
            } catch (e) {
                console.log("[Native Dump] 搜索函数失败: " + e);
            }
        }
    });
    
    // 保存搜索结果
    if (results.length > 0) {
        const timestamp = new Date().getTime();
        const outputPath = outputDir + "/" + timestamp + "_function_search.json";
        
        try {
            fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
            console.log("[Native Dump] 函数搜索结果已保存: " + outputPath);
        } catch (e) {
            console.log("[Native Dump] 保存搜索结果失败: " + e);
        }
    }
}

// 主执行流程
setTimeout(function() {
    console.log("[Native Dump] 开始执行分析...");
    
    // 1. 导出当前已加载的模块
    dumpLoadedModules();
    
    // 2. Hook 动态加载函数
    hookDlopen();
    hookAndroidDlopen();
    
    // 3. 搜索常见的加密和网络函数
    const searchPatterns = [
        "encrypt", "decrypt", "cipher", "hash", "md5", "sha", "aes", "rsa",
        "ssl", "tls", "http", "socket", "connect", "send", "recv",
        "malloc", "free", "mmap", "mprotect"
    ];
    searchFunctions(searchPatterns);
    
    console.log("[Native Dump] 分析完成，结果保存在: " + outputDir);
    
}, 3000);

console.log("[Native Dump] Native 层导出脚本已启动");
console.log("[Native Dump] 输出目录: " + outputDir);
console.log("[Native Dump] 目标库: " + targetLibs.join(", "));

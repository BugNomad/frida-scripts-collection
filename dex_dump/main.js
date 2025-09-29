/**
 * DEX 文件导出脚本
 * 自动导出 Android 应用的 DEX 文件
 */

Java.perform(function() {
    console.log("[DEX Dump] 开始 DEX 文件导出...");
    
    const outputDir = "/data/local/tmp/dex_dump";
    const File = Java.use("java.io.File");
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    
    // 创建输出目录
    try {
        const dir = File.$new(outputDir);
        if (!dir.exists()) {
            dir.mkdirs();
            console.log("[DEX Dump] 创建输出目录: " + outputDir);
        }
    } catch (e) {
        console.log("[DEX Dump] 创建目录失败: " + e);
    }
    
    // 获取当前应用的 ClassLoader
    const currentApplication = Java.use("android.app.ActivityThread").currentApplication();
    const context = currentApplication.getApplicationContext();
    const classLoader = context.getClassLoader();
    
    console.log("[DEX Dump] 当前 ClassLoader: " + classLoader);
    
    // Hook DexFile 类来获取 DEX 文件信息
    try {
        const DexFile = Java.use("dalvik.system.DexFile");
        
        DexFile.loadDex.overload('java.lang.String', 'java.lang.String', 'int').implementation = function(sourcePathName, outputPathName, flags) {
            console.log("[DEX Dump] DexFile.loadDex 调用:");
            console.log("  源路径: " + sourcePathName);
            console.log("  输出路径: " + outputPathName);
            console.log("  标志: " + flags);
            
            const result = this.loadDex(sourcePathName, outputPathName, flags);
            
            // 尝试复制 DEX 文件
            if (sourcePathName && sourcePathName.endsWith(".dex")) {
                dumpDexFile(sourcePathName);
            }
            
            return result;
        };
        
        console.log("[DEX Dump] 已 Hook DexFile.loadDex");
    } catch (e) {
        console.log("[DEX Dump] Hook DexFile 失败: " + e);
    }
    
    // Hook BaseDexClassLoader 来获取 DEX 路径
    try {
        const BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
        
        BaseDexClassLoader.$init.overload('java.lang.String', 'java.io.File', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
            console.log("[DEX Dump] BaseDexClassLoader 初始化:");
            console.log("  DEX 路径: " + dexPath);
            console.log("  优化目录: " + optimizedDirectory);
            console.log("  库搜索路径: " + librarySearchPath);
            
            // 解析 DEX 路径并导出
            if (dexPath) {
                const paths = dexPath.split(":");
                for (let i = 0; i < paths.length; i++) {
                    const path = paths[i];
                    if (path && (path.endsWith(".dex") || path.endsWith(".apk") || path.endsWith(".jar"))) {
                        dumpDexFile(path);
                    }
                }
            }
            
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
        
        console.log("[DEX Dump] 已 Hook BaseDexClassLoader");
    } catch (e) {
        console.log("[DEX Dump] Hook BaseDexClassLoader 失败: " + e);
    }
    
    // 导出 DEX 文件的函数
    function dumpDexFile(sourcePath) {
        try {
            console.log("[DEX Dump] 尝试导出: " + sourcePath);
            
            const sourceFile = File.$new(sourcePath);
            if (!sourceFile.exists()) {
                console.log("[DEX Dump] 源文件不存在: " + sourcePath);
                return;
            }
            
            const fileName = sourceFile.getName();
            const timestamp = new Date().getTime();
            const outputPath = outputDir + "/" + timestamp + "_" + fileName;
            
            // 读取源文件
            const FileInputStream = Java.use("java.io.FileInputStream");
            const inputStream = FileInputStream.$new(sourceFile);
            const outputFile = File.$new(outputPath);
            const outputStream = FileOutputStream.$new(outputFile);
            
            // 复制文件
            const buffer = Java.array('byte', 8192);
            let bytesRead;
            while ((bytesRead = inputStream.read(buffer)) !== -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            
            inputStream.close();
            outputStream.close();
            
            console.log("[DEX Dump] 成功导出: " + outputPath);
            console.log("[DEX Dump] 文件大小: " + outputFile.length() + " bytes");
            
        } catch (e) {
            console.log("[DEX Dump] 导出失败: " + e);
        }
    }
    
    // 主动扫描并导出当前应用的 DEX 文件
    function scanAndDumpCurrentApp() {
        try {
            const packageManager = context.getPackageManager();
            const packageName = context.getPackageName();
            const packageInfo = packageManager.getPackageInfo(packageName, 0);
            const applicationInfo = packageInfo.applicationInfo;
            
            console.log("[DEX Dump] 当前应用: " + packageName);
            console.log("[DEX Dump] APK 路径: " + applicationInfo.sourceDir.value);
            
            // 导出主 APK
            dumpDexFile(applicationInfo.sourceDir.value);
            
            // 导出分包 APK (如果有)
            if (applicationInfo.splitSourceDirs.value) {
                const splitDirs = applicationInfo.splitSourceDirs.value;
                for (let i = 0; i < splitDirs.length; i++) {
                    dumpDexFile(splitDirs[i]);
                }
            }
            
        } catch (e) {
            console.log("[DEX Dump] 扫描当前应用失败: " + e);
        }
    }
    
    // 延迟执行主动扫描
    setTimeout(function() {
        scanAndDumpCurrentApp();
    }, 2000);
    
    console.log("[DEX Dump] DEX 导出脚本已启动");
    console.log("[DEX Dump] 输出目录: " + outputDir);
});

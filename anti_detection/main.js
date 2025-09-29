/**
 * 反检测脚本
 * 绕过常见的 Frida 检测机制
 */

// 环境变量配置
var config = {
    enableLogging: true,
    hideFromPS: true,
    spoofMaps: true,
    hideThreads: true
};

// 日志函数
function log(message, level) {
    level = level || "info";
    var logData = {
        type: "log",
        payload: {
            level: level,
            message: message,
            timestamp: Date.now()
        }
    };
    
    send(logData);
    
    if (config.enableLogging) {
        console.log("[Anti-Detection] " + message);
    }
}

// Android 反检测
function androidAntiDetection() {
    if (!Java.available) {
        log("Java runtime not available", "warning");
        return;
    }
    
    Java.perform(function() {
        try {
            // 1. 隐藏 Frida 相关的包名和进程
            try {
                var ActivityManager = Java.use("android.app.ActivityManager");
                ActivityManager.getRunningServices.implementation = function(maxNum) {
                    var services = this.getRunningServices(maxNum);
                    var filteredServices = [];
                    
                    for (var i = 0; i < services.size(); i++) {
                        var service = services.get(i);
                        var serviceName = service.service.getClassName();
                        
                        // 过滤 Frida 相关服务
                        if (!serviceName.includes("frida") && !serviceName.includes("gum")) {
                            filteredServices.push(service);
                        }
                    }
                    
                    log("ActivityManager.getRunningServices() filtered " + (services.size() - filteredServices.length) + " Frida services");
                    return Java.use("java.util.ArrayList").$new(filteredServices);
                };
                
                ActivityManager.getRunningAppProcesses.implementation = function() {
                    var processes = this.getRunningAppProcesses();
                    var filteredProcesses = [];
                    
                    for (var i = 0; i < processes.size(); i++) {
                        var process = processes.get(i);
                        var processName = process.processName.value;
                        
                        // 过滤 Frida 相关进程
                        if (!processName.includes("frida") && !processName.includes("gum")) {
                            filteredProcesses.push(process);
                        }
                    }
                    
                    log("ActivityManager.getRunningAppProcesses() filtered " + (processes.size() - filteredProcesses.length) + " Frida processes");
                    return Java.use("java.util.ArrayList").$new(filteredProcesses);
                };
                
                log("ActivityManager anti-detection enabled");
            } catch (e) {
                log("ActivityManager hook failed: " + e.message, "warning");
            }
            
            // 2. 隐藏 /proc/self/maps 中的 Frida 痕迹
            try {
                var File = Java.use("java.io.File");
                File.exists.implementation = function() {
                    var path = this.getAbsolutePath();
                    if (path.includes("frida") || path.includes("gum") || path.includes("linjector")) {
                        log("File.exists() blocked for: " + path);
                        return false;
                    }
                    return this.exists();
                };
                
                var FileInputStream = Java.use("java.io.FileInputStream");
                FileInputStream.$init.overload("java.io.File").implementation = function(file) {
                    var path = file.getAbsolutePath();
                    if (path.includes("/proc/") && (path.includes("maps") || path.includes("status"))) {
                        log("FileInputStream blocked for: " + path);
                        throw Java.use("java.io.FileNotFoundException").$new("File not found");
                    }
                    return this.$init(file);
                };
                
                log("File system anti-detection enabled");
            } catch (e) {
                log("File system hook failed: " + e.message, "warning");
            }
            
            // 3. 绕过 Native 层检测
            try {
                var System = Java.use("java.lang.System");
                System.getProperty.implementation = function(key) {
                    var result = this.getProperty(key);
                    
                    // 隐藏调试相关属性
                    if (key === "ro.debuggable" || key === "ro.secure") {
                        log("System.getProperty() spoofed for: " + key);
                        return "0";
                    }
                    
                    return result;
                };
                
                log("System properties anti-detection enabled");
            } catch (e) {
                log("System properties hook failed: " + e.message, "warning");
            }
            
            // 4. 绕过包管理器检测
            try {
                var PackageManager = Java.use("android.content.pm.PackageManager");
                PackageManager.getInstalledPackages.overload("int").implementation = function(flags) {
                    var packages = this.getInstalledPackages(flags);
                    var filteredPackages = [];
                    
                    for (var i = 0; i < packages.size(); i++) {
                        var pkg = packages.get(i);
                        var packageName = pkg.packageName.value;
                        
                        // 过滤调试和分析工具
                        if (!packageName.includes("frida") && 
                            !packageName.includes("xposed") && 
                            !packageName.includes("substrate") &&
                            !packageName.includes("supersu") &&
                            !packageName.includes("magisk")) {
                            filteredPackages.push(pkg);
                        }
                    }
                    
                    log("PackageManager.getInstalledPackages() filtered " + (packages.size() - filteredPackages.length) + " suspicious packages");
                    return Java.use("java.util.ArrayList").$new(filteredPackages);
                };
                
                log("PackageManager anti-detection enabled");
            } catch (e) {
                log("PackageManager hook failed: " + e.message, "warning");
            }
            
            // 5. 绕过线程检测
            try {
                var Thread = Java.use("java.lang.Thread");
                Thread.getAllStackTraces.implementation = function() {
                    var traces = this.getAllStackTraces();
                    log("Thread.getAllStackTraces() called - potential detection attempt");
                    return traces;
                };
                
                log("Thread anti-detection enabled");
            } catch (e) {
                log("Thread hook failed: " + e.message, "warning");
            }
            
        } catch (e) {
            log("Error in Android anti-detection: " + e.message, "error");
        }
    });
}

// Native 层反检测
function nativeAntiDetection() {
    try {
        // 1. Hook dlopen 来隐藏 Frida 库
        var dlopen = Module.findExportByName(null, "dlopen");
        if (dlopen) {
            Interceptor.attach(dlopen, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    if (path && (path.includes("frida") || path.includes("gum"))) {
                        log("dlopen() blocked for: " + path);
                        args[0] = Memory.allocUtf8String("/system/lib/libc.so"); // 重定向到系统库
                    }
                }
            });
            log("dlopen anti-detection enabled");
        }
        
        // 2. Hook fopen 来隐藏 /proc 文件
        var fopen = Module.findExportByName(null, "fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    if (path && path.includes("/proc/") && 
                        (path.includes("maps") || path.includes("status") || path.includes("stat"))) {
                        log("fopen() blocked for: " + path);
                        args[0] = Memory.allocUtf8String("/dev/null");
                    }
                }
            });
            log("fopen anti-detection enabled");
        }
        
        // 3. Hook strstr 来隐藏字符串检测
        var strstr = Module.findExportByName(null, "strstr");
        if (strstr) {
            Interceptor.attach(strstr, {
                onEnter: function(args) {
                    var haystack = Memory.readUtf8String(args[0]);
                    var needle = Memory.readUtf8String(args[1]);
                    
                    if (needle && (needle.includes("frida") || needle.includes("gum") || needle.includes("linjector"))) {
                        log("strstr() detection attempt for: " + needle);
                        this.replace = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.replace) {
                        retval.replace(ptr(0)); // 返回 NULL
                    }
                }
            });
            log("strstr anti-detection enabled");
        }
        
    } catch (e) {
        log("Error in native anti-detection: " + e.message, "error");
    }
}

// iOS 反检测
function iOSAntiDetection() {
    if (!ObjC.available) {
        log("Objective-C runtime not available", "warning");
        return;
    }
    
    try {
        // 1. 绕过 sysctl 检测
        var sysctl = Module.findExportByName(null, "sysctl");
        if (sysctl) {
            Interceptor.attach(sysctl, {
                onEnter: function(args) {
                    var name = Memory.readPointer(args[0]);
                    var namelen = args[1].toInt32();
                    
                    if (namelen > 0) {
                        var nameArray = [];
                        for (var i = 0; i < namelen; i++) {
                            nameArray.push(Memory.readU32(name.add(i * 4)));
                        }
                        
                        // 检测是否在查询进程信息
                        if (nameArray[0] === 1 && nameArray[1] === 14) { // CTL_KERN, KERN_PROC
                            log("sysctl() process detection attempt blocked");
                            this.block = true;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.block) {
                        retval.replace(-1); // 返回错误
                    }
                }
            });
            log("sysctl anti-detection enabled");
        }
        
        // 2. 绕过 dyld 检测
        var dyld_get_image_name = Module.findExportByName(null, "_dyld_get_image_name");
        if (dyld_get_image_name) {
            Interceptor.attach(dyld_get_image_name, {
                onLeave: function(retval) {
                    if (retval.isNull()) return;
                    
                    var imageName = Memory.readUtf8String(retval);
                    if (imageName && (imageName.includes("frida") || imageName.includes("gum"))) {
                        log("dyld_get_image_name() blocked for: " + imageName);
                        retval.replace(Memory.allocUtf8String("/usr/lib/system/libsystem_c.dylib"));
                    }
                }
            });
            log("dyld anti-detection enabled");
        }
        
    } catch (e) {
        log("Error in iOS anti-detection: " + e.message, "error");
    }
}

// 主函数
function main() {
    log("Starting anti-detection script");
    
    // 应用 Native 层反检测（通用）
    nativeAntiDetection();
    
    // 根据平台应用特定反检测
    if (Java.available) {
        log("Android platform detected");
        androidAntiDetection();
    } else if (ObjC.available) {
        log("iOS platform detected");
        iOSAntiDetection();
    } else {
        log("Unknown platform", "warning");
    }
    
    log("Anti-detection script initialized");
}

// 启动脚本
main();

// 导出配置供外部调用
rpc.exports = {
    setConfig: function(newConfig) {
        Object.assign(config, newConfig);
        log("Configuration updated: " + JSON.stringify(config));
    },
    getConfig: function() {
        return config;
    }
};

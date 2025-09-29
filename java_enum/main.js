/**
 * Java 类和方法枚举脚本
 * 枚举 Android 应用中的 Java 类、方法和字段
 */

Java.perform(function() {
    console.log("[Java Enum] Java 类枚举工具启动...");
    
    const outputDir = "/data/local/tmp/java_enum";
    const targetPackages = ["com.example", "com.app"]; // 可配置目标包名
    
    const File = Java.use("java.io.File");
    const FileWriter = Java.use("java.io.FileWriter");
    const BufferedWriter = Java.use("java.io.BufferedWriter");
    
    // 创建输出目录
    try {
        const dir = File.$new(outputDir);
        if (!dir.exists()) {
            dir.mkdirs();
            console.log("[Java Enum] 创建输出目录: " + outputDir);
        }
    } catch (e) {
        console.log("[Java Enum] 创建目录失败: " + e);
    }
    
    // 获取当前应用包名
    const currentApplication = Java.use("android.app.ActivityThread").currentApplication();
    const context = currentApplication.getApplicationContext();
    const packageName = context.getPackageName();
    
    console.log("[Java Enum] 当前应用包名: " + packageName);
    
    // 枚举结果存储
    const enumResults = {
        package_name: packageName,
        timestamp: new Date().toISOString(),
        classes: [],
        statistics: {
            total_classes: 0,
            total_methods: 0,
            total_fields: 0,
            target_classes: 0
        }
    };
    
    // 检查是否为目标包
    function isTargetPackage(className) {
        if (className.startsWith(packageName)) {
            return true;
        }
        
        return targetPackages.some(pkg => className.startsWith(pkg));
    }
    
    // 枚举类信息
    function enumerateClass(className) {
        try {
            const clazz = Java.use(className);
            const classInfo = {
                name: className,
                methods: [],
                fields: [],
                constructors: [],
                interfaces: [],
                superclass: null
            };
            
            // 获取类的反射对象
            const javaClass = clazz.class;
            
            // 父类信息
            try {
                const superClass = javaClass.getSuperclass();
                if (superClass) {
                    classInfo.superclass = superClass.getName();
                }
            } catch (e) {
                // 忽略错误
            }
            
            // 接口信息
            try {
                const interfaces = javaClass.getInterfaces();
                for (let i = 0; i < interfaces.length; i++) {
                    classInfo.interfaces.push(interfaces[i].getName());
                }
            } catch (e) {
                // 忽略错误
            }
            
            // 方法信息
            try {
                const methods = javaClass.getDeclaredMethods();
                for (let i = 0; i < methods.length; i++) {
                    const method = methods[i];
                    const methodInfo = {
                        name: method.getName(),
                        modifiers: method.getModifiers(),
                        return_type: method.getReturnType().getName(),
                        parameters: []
                    };
                    
                    // 参数类型
                    const paramTypes = method.getParameterTypes();
                    for (let j = 0; j < paramTypes.length; j++) {
                        methodInfo.parameters.push(paramTypes[j].getName());
                    }
                    
                    classInfo.methods.push(methodInfo);
                    enumResults.statistics.total_methods++;
                }
            } catch (e) {
                console.log("[Java Enum] 获取方法失败: " + className + " - " + e);
            }
            
            // 字段信息
            try {
                const fields = javaClass.getDeclaredFields();
                for (let i = 0; i < fields.length; i++) {
                    const field = fields[i];
                    const fieldInfo = {
                        name: field.getName(),
                        type: field.getType().getName(),
                        modifiers: field.getModifiers()
                    };
                    
                    classInfo.fields.push(fieldInfo);
                    enumResults.statistics.total_fields++;
                }
            } catch (e) {
                console.log("[Java Enum] 获取字段失败: " + className + " - " + e);
            }
            
            // 构造函数信息
            try {
                const constructors = javaClass.getDeclaredConstructors();
                for (let i = 0; i < constructors.length; i++) {
                    const constructor = constructors[i];
                    const constructorInfo = {
                        modifiers: constructor.getModifiers(),
                        parameters: []
                    };
                    
                    const paramTypes = constructor.getParameterTypes();
                    for (let j = 0; j < paramTypes.length; j++) {
                        constructorInfo.parameters.push(paramTypes[j].getName());
                    }
                    
                    classInfo.constructors.push(constructorInfo);
                }
            } catch (e) {
                console.log("[Java Enum] 获取构造函数失败: " + className + " - " + e);
            }
            
            enumResults.classes.push(classInfo);
            enumResults.statistics.total_classes++;
            
            if (isTargetPackage(className)) {
                enumResults.statistics.target_classes++;
                console.log("[Java Enum] 枚举目标类: " + className + 
                           " (方法: " + classInfo.methods.length + 
                           ", 字段: " + classInfo.fields.length + ")");
            }
            
        } catch (e) {
            console.log("[Java Enum] 枚举类失败: " + className + " - " + e);
        }
    }
    
    // 枚举已加载的类
    function enumerateLoadedClasses() {
        console.log("[Java Enum] 开始枚举已加载的类...");
        
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                // 只处理目标包的类，避免输出过多
                if (isTargetPackage(className)) {
                    enumerateClass(className);
                }
            },
            onComplete: function() {
                console.log("[Java Enum] 类枚举完成");
                saveResults();
            }
        });
    }
    
    // Hook ClassLoader 来监控新加载的类
    function hookClassLoader() {
        try {
            const ClassLoader = Java.use("java.lang.ClassLoader");
            
            ClassLoader.loadClass.overload('java.lang.String').implementation = function(className) {
                const result = this.loadClass(className);
                
                if (isTargetPackage(className)) {
                    console.log("[Java Enum] 新加载的目标类: " + className);
                    setTimeout(function() {
                        enumerateClass(className);
                    }, 100);
                }
                
                return result;
            };
            
            console.log("[Java Enum] 已 Hook ClassLoader.loadClass");
        } catch (e) {
            console.log("[Java Enum] Hook ClassLoader 失败: " + e);
        }
    }
    
    // 搜索特定模式的类和方法
    function searchPatterns() {
        console.log("[Java Enum] 搜索特定模式...");
        
        const patterns = {
            crypto: ["encrypt", "decrypt", "cipher", "hash", "md5", "sha", "aes", "rsa"],
            network: ["http", "url", "socket", "connect", "request", "response"],
            auth: ["login", "auth", "token", "password", "credential"],
            storage: ["database", "sqlite", "file", "storage", "cache", "preference"]
        };
        
        const patternResults = {};
        
        Object.keys(patterns).forEach(function(category) {
            patternResults[category] = [];
            
            enumResults.classes.forEach(function(classInfo) {
                // 搜索类名
                patterns[category].forEach(function(pattern) {
                    if (classInfo.name.toLowerCase().includes(pattern)) {
                        patternResults[category].push({
                            type: "class",
                            name: classInfo.name,
                            pattern: pattern
                        });
                    }
                });
                
                // 搜索方法名
                classInfo.methods.forEach(function(method) {
                    patterns[category].forEach(function(pattern) {
                        if (method.name.toLowerCase().includes(pattern)) {
                            patternResults[category].push({
                                type: "method",
                                class: classInfo.name,
                                name: method.name,
                                pattern: pattern
                            });
                        }
                    });
                });
            });
        });
        
        enumResults.pattern_matches = patternResults;
        
        // 输出搜索结果
        Object.keys(patternResults).forEach(function(category) {
            if (patternResults[category].length > 0) {
                console.log("[Java Enum] " + category + " 模式匹配: " + patternResults[category].length + " 个");
            }
        });
    }
    
    // 保存枚举结果
    function saveResults() {
        try {
            // 搜索模式
            searchPatterns();
            
            const timestamp = new Date().getTime();
            const outputPath = outputDir + "/" + timestamp + "_java_enum.json";
            
            const jsonString = JSON.stringify(enumResults, null, 2);
            
            const file = File.$new(outputPath);
            const writer = FileWriter.$new(file);
            const bufferedWriter = BufferedWriter.$new(writer);
            
            bufferedWriter.write(jsonString);
            bufferedWriter.close();
            writer.close();
            
            console.log("[Java Enum] 枚举结果已保存: " + outputPath);
            console.log("[Java Enum] 统计信息:");
            console.log("  总类数: " + enumResults.statistics.total_classes);
            console.log("  目标类数: " + enumResults.statistics.target_classes);
            console.log("  总方法数: " + enumResults.statistics.total_methods);
            console.log("  总字段数: " + enumResults.statistics.total_fields);
            
        } catch (e) {
            console.log("[Java Enum] 保存结果失败: " + e);
        }
    }
    
    // 主执行流程
    setTimeout(function() {
        console.log("[Java Enum] 开始执行枚举...");
        
        // 1. Hook ClassLoader 监控新类加载
        hookClassLoader();
        
        // 2. 枚举当前已加载的类
        enumerateLoadedClasses();
        
    }, 2000);
    
    console.log("[Java Enum] Java 类枚举脚本已启动");
    console.log("[Java Enum] 目标包名: " + targetPackages.join(", "));
    console.log("[Java Enum] 输出目录: " + outputDir);
});

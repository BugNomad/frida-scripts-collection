// 测试脚本 - 简单的日志输出
console.log("[+] Test script loaded successfully!");

// 如果是 Android 环境，尝试 Hook Java 方法
if (Java.available) {
    console.log("[+] Java runtime detected");
    
    Java.perform(function() {
        console.log("[+] Inside Java.perform");
        
        try {
            // Hook Log.d 方法来演示基本功能
            var Log = Java.use("android.util.Log");
            
            Log.d.overload("java.lang.String", "java.lang.String").implementation = function(tag, msg) {
                console.log("[HOOK] Log.d called: " + tag + " -> " + msg);
                return this.d(tag, msg);
            };
            
            console.log("[+] Successfully hooked android.util.Log.d");
            
            // 主动调用一次来测试
            Log.d("FridaTest", "Hook is working!");
            
        } catch (e) {
            console.log("[-] Error hooking Log.d: " + e.message);
        }
    });
} else {
    console.log("[+] Non-Java environment detected");
}

console.log("[+] Test script setup complete");

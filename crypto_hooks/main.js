/**
 * 加密函数 Hook 脚本
 * 监控常见的加密算法调用，记录输入输出参数
 */

// 环境变量配置
var config = {
    enableLogging: true,
    reportUrl: "http://localhost:8000/api/hooks/crypto",
    maxDataLength: 1024,
    enableBase64: true,
    enableAES: true,
    enableRSA: true,
    enableHash: true
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
        console.log("[Crypto Hook] " + message);
    }
}

// 数据格式化函数
function formatData(data, maxLength) {
    if (!data) return "null";
    
    maxLength = maxLength || config.maxDataLength;
    var str = "";
    
    if (typeof data === "string") {
        str = data;
    } else if (data instanceof ArrayBuffer) {
        str = Array.from(new Uint8Array(data)).map(b => b.toString(16).padStart(2, '0')).join('');
    } else if (Array.isArray(data)) {
        str = data.map(b => b.toString(16).padStart(2, '0')).join('');
    } else {
        str = data.toString();
    }
    
    if (str.length > maxLength) {
        str = str.substring(0, maxLength) + "...";
    }
    
    return str;
}

// 发送加密事件
function sendCryptoEvent(algorithm, operation, input, output, key, iv) {
    var eventData = {
        type: "crypto",
        payload: {
            algorithm: algorithm,
            operation: operation,
            input: formatData(input),
            output: formatData(output),
            key: formatData(key),
            iv: formatData(iv),
            timestamp: Date.now(),
            stackTrace: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n')
        }
    };
    
    send(eventData);
}

// Android 加密 Hook
function androidCryptoHooks() {
    if (!Java.available) {
        log("Java runtime not available", "warning");
        return;
    }
    
    Java.perform(function() {
        try {
            // 1. Base64 编码/解码
            if (config.enableBase64) {
                try {
                    var Base64 = Java.use("android.util.Base64");
                    
                    // Hook encode
                    Base64.encode.overload("[B", "int").implementation = function(input, flags) {
                        var result = this.encode(input, flags);
                        var inputStr = formatData(input);
                        var outputStr = formatData(result);
                        
                        log("Base64.encode() - Input: " + inputStr + " -> Output: " + outputStr);
                        sendCryptoEvent("Base64", "encode", input, result, null, null);
                        
                        return result;
                    };
                    
                    // Hook decode
                    Base64.decode.overload("java.lang.String", "int").implementation = function(input, flags) {
                        var result = this.decode(input, flags);
                        var inputStr = formatData(input);
                        var outputStr = formatData(result);
                        
                        log("Base64.decode() - Input: " + inputStr + " -> Output: " + outputStr);
                        sendCryptoEvent("Base64", "decode", input, result, null, null);
                        
                        return result;
                    };
                    
                    log("Base64 hooks enabled");
                } catch (e) {
                    log("Base64 hook failed: " + e.message, "warning");
                }
            }
            
            // 2. AES 加密/解密
            if (config.enableAES) {
                try {
                    var Cipher = Java.use("javax.crypto.Cipher");
                    
                    // Hook doFinal
                    Cipher.doFinal.overload("[B").implementation = function(input) {
                        var result = this.doFinal(input);
                        var algorithm = this.getAlgorithm();
                        var opMode = this.getOpmode();
                        var operation = (opMode === 1) ? "encrypt" : "decrypt";
                        
                        var inputStr = formatData(input);
                        var outputStr = formatData(result);
                        
                        log(algorithm + "." + operation + "() - Input: " + inputStr + " -> Output: " + outputStr);
                        sendCryptoEvent(algorithm, operation, input, result, null, null);
                        
                        return result;
                    };
                    
                    // Hook init 来获取密钥
                    Cipher.init.overload("int", "java.security.Key").implementation = function(opmode, key) {
                        var keyData = null;
                        try {
                            keyData = key.getEncoded();
                        } catch (e) {
                            keyData = "Key not extractable";
                        }
                        
                        var operation = (opmode === 1) ? "encrypt" : "decrypt";
                        log("Cipher.init() - Mode: " + operation + ", Key: " + formatData(keyData));
                        
                        return this.init(opmode, key);
                    };
                    
                    log("AES/Cipher hooks enabled");
                } catch (e) {
                    log("AES/Cipher hook failed: " + e.message, "warning");
                }
            }
            
            // 3. Hash 函数 (MD5, SHA)
            if (config.enableHash) {
                try {
                    var MessageDigest = Java.use("java.security.MessageDigest");
                    
                    MessageDigest.digest.overload("[B").implementation = function(input) {
                        var result = this.digest(input);
                        var algorithm = this.getAlgorithm();
                        
                        var inputStr = formatData(input);
                        var outputStr = formatData(result);
                        
                        log(algorithm + ".digest() - Input: " + inputStr + " -> Output: " + outputStr);
                        sendCryptoEvent(algorithm, "hash", input, result, null, null);
                        
                        return result;
                    };
                    
                    log("MessageDigest hooks enabled");
                } catch (e) {
                    log("MessageDigest hook failed: " + e.message, "warning");
                }
            }
            
            // 4. RSA 加密/解密
            if (config.enableRSA) {
                try {
                    var RSAPublicKey = Java.use("java.security.interfaces.RSAPublicKey");
                    var RSAPrivateKey = Java.use("java.security.interfaces.RSAPrivateKey");
                    
                    // 这里可以添加更多 RSA 相关的 Hook
                    log("RSA key interfaces hooked");
                } catch (e) {
                    log("RSA hook failed: " + e.message, "warning");
                }
            }
            
            // 5. 常见的第三方加密库
            try {
                // Hook OkHttp 的加密相关方法
                var CipherSuite = Java.use("okhttp3.CipherSuite");
                log("OkHttp CipherSuite found");
            } catch (e) {
                log("OkHttp not found: " + e.message, "debug");
            }
            
        } catch (e) {
            log("Error in Android crypto hooks: " + e.message, "error");
        }
    });
}

// Native 层加密 Hook
function nativeCryptoHooks() {
    try {
        // 1. OpenSSL hooks
        var openssl_modules = ["libssl.so", "libcrypto.so"];
        
        openssl_modules.forEach(function(moduleName) {
            var module = Module.findByName(moduleName);
            if (module) {
                log("Found OpenSSL module: " + moduleName);
                
                // Hook AES_encrypt
                var AES_encrypt = Module.findExportByName(moduleName, "AES_encrypt");
                if (AES_encrypt) {
                    Interceptor.attach(AES_encrypt, {
                        onEnter: function(args) {
                            this.input = Memory.readByteArray(args[0], 16);
                            this.key = Memory.readByteArray(args[1], 16);
                        },
                        onLeave: function(retval) {
                            var output = Memory.readByteArray(this.context.x1, 16);
                            log("AES_encrypt() called");
                            sendCryptoEvent("AES", "encrypt", this.input, output, this.key, null);
                        }
                    });
                    log("AES_encrypt hook enabled");
                }
                
                // Hook AES_decrypt
                var AES_decrypt = Module.findExportByName(moduleName, "AES_decrypt");
                if (AES_decrypt) {
                    Interceptor.attach(AES_decrypt, {
                        onEnter: function(args) {
                            this.input = Memory.readByteArray(args[0], 16);
                            this.key = Memory.readByteArray(args[1], 16);
                        },
                        onLeave: function(retval) {
                            var output = Memory.readByteArray(this.context.x1, 16);
                            log("AES_decrypt() called");
                            sendCryptoEvent("AES", "decrypt", this.input, output, this.key, null);
                        }
                    });
                    log("AES_decrypt hook enabled");
                }
            }
        });
        
        // 2. 通用加密函数 Hook
        var encrypt_functions = ["encrypt", "decrypt", "hash", "md5", "sha1", "sha256"];
        
        encrypt_functions.forEach(function(funcName) {
            var func = Module.findExportByName(null, funcName);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: function(args) {
                        log("Native function " + funcName + "() called");
                    }
                });
            }
        });
        
    } catch (e) {
        log("Error in native crypto hooks: " + e.message, "error");
    }
}

// iOS 加密 Hook
function iOSCryptoHooks() {
    if (!ObjC.available) {
        log("Objective-C runtime not available", "warning");
        return;
    }
    
    try {
        // 1. CommonCrypto hooks
        var CCCrypt = Module.findExportByName("CommonCrypto", "CCCrypt");
        if (CCCrypt) {
            Interceptor.attach(CCCrypt, {
                onEnter: function(args) {
                    var op = args[0].toInt32();
                    var alg = args[1].toInt32();
                    var options = args[2].toInt32();
                    var keyLength = args[4].toInt32();
                    var dataInLength = args[6].toInt32();
                    
                    this.operation = (op === 0) ? "encrypt" : "decrypt";
                    this.algorithm = "CCCrypt_" + alg;
                    this.input = Memory.readByteArray(args[5], Math.min(dataInLength, 256));
                    this.key = Memory.readByteArray(args[3], Math.min(keyLength, 64));
                },
                onLeave: function(retval) {
                    log("CCCrypt() - " + this.algorithm + "." + this.operation);
                    sendCryptoEvent(this.algorithm, this.operation, this.input, null, this.key, null);
                }
            });
            log("CCCrypt hook enabled");
        }
        
        // 2. Security Framework hooks
        var SecKeyEncrypt = Module.findExportByName("Security", "SecKeyEncrypt");
        if (SecKeyEncrypt) {
            Interceptor.attach(SecKeyEncrypt, {
                onEnter: function(args) {
                    var dataLength = args[2].toInt32();
                    this.input = Memory.readByteArray(args[1], Math.min(dataLength, 256));
                },
                onLeave: function(retval) {
                    log("SecKeyEncrypt() called");
                    sendCryptoEvent("SecKey", "encrypt", this.input, null, null, null);
                }
            });
            log("SecKeyEncrypt hook enabled");
        }
        
    } catch (e) {
        log("Error in iOS crypto hooks: " + e.message, "error");
    }
}

// 主函数
function main() {
    log("Starting crypto hooks script");
    
    // 应用 Native 层 Hook（通用）
    nativeCryptoHooks();
    
    // 根据平台应用特定 Hook
    if (Java.available) {
        log("Android platform detected");
        androidCryptoHooks();
    } else if (ObjC.available) {
        log("iOS platform detected");
        iOSCryptoHooks();
    } else {
        log("Unknown platform", "warning");
    }
    
    log("Crypto hooks script initialized");
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

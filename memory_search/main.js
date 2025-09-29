/**
 * 内存搜索工具
 * 在进程内存中搜索字符串、字节序列等
 */

console.log("[Memory Search] 内存搜索工具启动...");

const outputDir = "/data/local/tmp/memory_search";
const searchStrings = ["password", "token", "key", "secret", "api", "auth"];
const searchHexPatterns = ["deadbeef", "cafebabe", "feedface"];

// 创建输出目录
const fs = require('fs');
try {
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
        console.log("[Memory Search] 创建输出目录: " + outputDir);
    }
} catch (e) {
    console.log("[Memory Search] 创建目录失败: " + e);
}

// 搜索结果存储
let searchResults = [];

// 字符串搜索函数
function searchStringInMemory(searchString) {
    console.log("[Memory Search] 搜索字符串: " + searchString);
    
    const ranges = Process.enumerateRanges('r--');
    let foundCount = 0;
    
    ranges.forEach(function(range) {
        try {
            // 跳过太小的内存区域
            if (range.size < searchString.length) {
                return;
            }
            
            // 读取内存内容
            const memory = Memory.readByteArray(range.base, range.size);
            const buffer = new Uint8Array(memory);
            const searchBytes = new TextEncoder().encode(searchString);
            
            // 搜索字符串
            for (let i = 0; i <= buffer.length - searchBytes.length; i++) {
                let match = true;
                for (let j = 0; j < searchBytes.length; j++) {
                    if (buffer[i + j] !== searchBytes[j]) {
                        match = false;
                        break;
                    }
                }
                
                if (match) {
                    const address = range.base.add(i);
                    const context = extractContext(buffer, i, searchString.length);
                    
                    const result = {
                        type: "string",
                        pattern: searchString,
                        address: address.toString(),
                        range: {
                            base: range.base.toString(),
                            size: range.size,
                            protection: range.protection
                        },
                        context: context,
                        timestamp: new Date().toISOString()
                    };
                    
                    searchResults.push(result);
                    foundCount++;
                    
                    console.log("[Memory Search] 找到字符串 '" + searchString + "' @ " + address);
                    console.log("[Memory Search] 上下文: " + context);
                }
            }
            
        } catch (e) {
            // 忽略无法读取的内存区域
        }
    });
    
    console.log("[Memory Search] 字符串 '" + searchString + "' 搜索完成，找到 " + foundCount + " 个匹配");
}

// 十六进制模式搜索
function searchHexInMemory(hexPattern) {
    console.log("[Memory Search] 搜索十六进制模式: " + hexPattern);
    
    const searchBytes = hexStringToBytes(hexPattern);
    if (!searchBytes) {
        console.log("[Memory Search] 无效的十六进制模式: " + hexPattern);
        return;
    }
    
    const ranges = Process.enumerateRanges('r--');
    let foundCount = 0;
    
    ranges.forEach(function(range) {
        try {
            if (range.size < searchBytes.length) {
                return;
            }
            
            const memory = Memory.readByteArray(range.base, range.size);
            const buffer = new Uint8Array(memory);
            
            for (let i = 0; i <= buffer.length - searchBytes.length; i++) {
                let match = true;
                for (let j = 0; j < searchBytes.length; j++) {
                    if (buffer[i + j] !== searchBytes[j]) {
                        match = false;
                        break;
                    }
                }
                
                if (match) {
                    const address = range.base.add(i);
                    const context = extractHexContext(buffer, i, searchBytes.length);
                    
                    const result = {
                        type: "hex",
                        pattern: hexPattern,
                        address: address.toString(),
                        range: {
                            base: range.base.toString(),
                            size: range.size,
                            protection: range.protection
                        },
                        context: context,
                        timestamp: new Date().toISOString()
                    };
                    
                    searchResults.push(result);
                    foundCount++;
                    
                    console.log("[Memory Search] 找到十六进制模式 '" + hexPattern + "' @ " + address);
                }
            }
            
        } catch (e) {
            // 忽略无法读取的内存区域
        }
    });
    
    console.log("[Memory Search] 十六进制模式 '" + hexPattern + "' 搜索完成，找到 " + foundCount + " 个匹配");
}

// 提取字符串上下文
function extractContext(buffer, position, patternLength) {
    const contextSize = 50;
    const start = Math.max(0, position - contextSize);
    const end = Math.min(buffer.length, position + patternLength + contextSize);
    
    let context = "";
    for (let i = start; i < end; i++) {
        const byte = buffer[i];
        if (byte >= 32 && byte <= 126) {
            context += String.fromCharCode(byte);
        } else {
            context += ".";
        }
    }
    
    return context;
}

// 提取十六进制上下文
function extractHexContext(buffer, position, patternLength) {
    const contextSize = 20;
    const start = Math.max(0, position - contextSize);
    const end = Math.min(buffer.length, position + patternLength + contextSize);
    
    let context = "";
    for (let i = start; i < end; i++) {
        context += buffer[i].toString(16).padStart(2, '0') + " ";
    }
    
    return context.trim();
}

// 十六进制字符串转字节数组
function hexStringToBytes(hexString) {
    try {
        const cleanHex = hexString.replace(/[^0-9a-fA-F]/g, '');
        if (cleanHex.length % 2 !== 0) {
            return null;
        }
        
        const bytes = [];
        for (let i = 0; i < cleanHex.length; i += 2) {
            bytes.push(parseInt(cleanHex.substr(i, 2), 16));
        }
        
        return new Uint8Array(bytes);
    } catch (e) {
        return null;
    }
}

// 搜索敏感信息模式
function searchSensitivePatterns() {
    console.log("[Memory Search] 搜索敏感信息模式...");
    
    const sensitivePatterns = [
        // 常见密钥格式
        /[A-Za-z0-9+\/]{32,}={0,2}/g,  // Base64
        /[0-9a-fA-F]{32,}/g,           // 十六进制密钥
        /[A-Z0-9]{20,}/g,              // API 密钥格式
        
        // 网络相关
        /https?:\/\/[^\s]+/g,          // URL
        /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, // IP 地址
        
        // 常见敏感字段
        /password["\s]*[:=]["\s]*[^"\s]+/gi,
        /token["\s]*[:=]["\s]*[^"\s]+/gi,
        /secret["\s]*[:=]["\s]*[^"\s]+/gi,
        /api[_-]?key["\s]*[:=]["\s]*[^"\s]+/gi
    ];
    
    const ranges = Process.enumerateRanges('r--');
    
    ranges.forEach(function(range) {
        try {
            if (range.size > 10 * 1024 * 1024) { // 跳过大于 10MB 的区域
                return;
            }
            
            const memory = Memory.readByteArray(range.base, range.size);
            const text = new TextDecoder('utf-8', { fatal: false }).decode(memory);
            
            sensitivePatterns.forEach(function(pattern, index) {
                const matches = text.match(pattern);
                if (matches) {
                    matches.forEach(function(match) {
                        const result = {
                            type: "pattern",
                            pattern: "sensitive_pattern_" + index,
                            match: match,
                            range: {
                                base: range.base.toString(),
                                size: range.size,
                                protection: range.protection
                            },
                            timestamp: new Date().toISOString()
                        };
                        
                        searchResults.push(result);
                        console.log("[Memory Search] 找到敏感模式: " + match);
                    });
                }
            });
            
        } catch (e) {
            // 忽略解码错误
        }
    });
}

// 保存搜索结果
function saveResults() {
    if (searchResults.length === 0) {
        console.log("[Memory Search] 没有找到任何匹配结果");
        return;
    }
    
    const timestamp = new Date().getTime();
    const outputPath = outputDir + "/" + timestamp + "_search_results.json";
    
    try {
        const summary = {
            total_results: searchResults.length,
            search_time: new Date().toISOString(),
            results: searchResults
        };
        
        fs.writeFileSync(outputPath, JSON.stringify(summary, null, 2));
        console.log("[Memory Search] 搜索结果已保存: " + outputPath);
        console.log("[Memory Search] 总共找到 " + searchResults.length + " 个匹配结果");
    } catch (e) {
        console.log("[Memory Search] 保存结果失败: " + e);
    }
}

// 主执行流程
setTimeout(function() {
    console.log("[Memory Search] 开始内存搜索...");
    
    // 1. 搜索字符串
    searchStrings.forEach(function(str) {
        searchStringInMemory(str);
    });
    
    // 2. 搜索十六进制模式
    searchHexPatterns.forEach(function(hex) {
        searchHexInMemory(hex);
    });
    
    // 3. 搜索敏感信息模式
    searchSensitivePatterns();
    
    // 4. 保存结果
    saveResults();
    
    console.log("[Memory Search] 内存搜索完成");
    
}, 2000);

console.log("[Memory Search] 内存搜索工具已启动");
console.log("[Memory Search] 搜索字符串: " + searchStrings.join(", "));
console.log("[Memory Search] 搜索十六进制: " + searchHexPatterns.join(", "));
console.log("[Memory Search] 输出目录: " + outputDir);

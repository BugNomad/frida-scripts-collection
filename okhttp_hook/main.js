/**
 * OkHttp 网络请求拦截脚本
 * 拦截 OkHttp3 库的网络请求并上报到后端
 */

// 环境变量配置
var config = {
    reportUrl: "http://localhost:8000/api/hooks/https",
    enableLogging: true,
    maxBodySize: 10240, // 最大请求/响应体大小 (bytes)
    excludeUrls: [
        "localhost:8000", // 排除上报接口本身
        "127.0.0.1:8000"
    ]
};

// 设置环境变量（从后端注入）
if (typeof setEnv !== 'undefined') {
    rpc.exports.setEnv = function(env) {
        Object.assign(config, env);
        log("Config updated: " + JSON.stringify(config));
    };
}

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
        console.log("[OkHttp Hook] " + message);
    }
}

// 检查 URL 是否应该被排除
function shouldExcludeUrl(url) {
    for (var i = 0; i < config.excludeUrls.length; i++) {
        if (url.indexOf(config.excludeUrls[i]) !== -1) {
            return true;
        }
    }
    return false;
}

// 截断过长的内容
function truncateContent(content, maxSize) {
    if (!content) return content;
    if (content.length <= maxSize) return content;
    return content.substring(0, maxSize) + "... [truncated]";
}

// 上报 HTTPS 事件到后端
function reportHttpsEvent(eventData) {
    if (shouldExcludeUrl(eventData.url)) {
        return;
    }
    
    // 发送到 WebSocket (通过 send 函数)
    send({
        type: "https_event",
        payload: eventData
    });
    
    // 也可以通过 HTTP POST 上报（可选）
    /*
    try {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", config.reportUrl, true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(JSON.stringify(eventData));
    } catch (e) {
        log("Failed to report event: " + e.message, "error");
    }
    */
}

// Hook OkHttp3
function hookOkHttp() {
    try {
        // Hook OkHttp3 Call.execute()
        var Call = Java.use("okhttp3.Call");
        Call.execute.implementation = function() {
            var request = this.request();
            var startTime = Date.now();
            
            // 获取请求信息
            var method = request.method();
            var url = request.url().toString();
            var reqHeaders = {};
            var reqBody = "";
            
            // 提取请求头
            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {
                var name = headers.name(i);
                var value = headers.value(i);
                reqHeaders[name] = value;
            }
            
            // 提取请求体
            try {
                var requestBody = request.body();
                if (requestBody != null) {
                    var buffer = Java.use("okio.Buffer").$new();
                    requestBody.writeTo(buffer);
                    reqBody = buffer.readUtf8();
                    reqBody = truncateContent(reqBody, config.maxBodySize);
                }
            } catch (e) {
                log("Failed to read request body: " + e.message, "warning");
            }
            
            log("Intercepted request: " + method + " " + url);
            
            // 执行原始请求
            var response = this.execute();
            var endTime = Date.now();
            
            // 获取响应信息
            var statusCode = response.code();
            var resHeaders = {};
            var resBody = "";
            
            // 提取响应头
            var responseHeaders = response.headers();
            for (var i = 0; i < responseHeaders.size(); i++) {
                var name = responseHeaders.name(i);
                var value = responseHeaders.value(i);
                resHeaders[name] = value;
            }
            
            // 提取响应体
            try {
                var responseBody = response.body();
                if (responseBody != null) {
                    var source = responseBody.source();
                    source.request(Java.use("java.lang.Long").MAX_VALUE);
                    var buffer = source.buffer();
                    resBody = buffer.clone().readUtf8();
                    resBody = truncateContent(resBody, config.maxBodySize);
                }
            } catch (e) {
                log("Failed to read response body: " + e.message, "warning");
            }
            
            // 上报事件
            var eventData = {
                id: "okhttp_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
                script_id: "okhttp_hook",
                method: method,
                url: url,
                req_headers: reqHeaders,
                req_body: reqBody,
                res_headers: resHeaders,
                res_body: resBody,
                status_code: statusCode,
                duration_ms: endTime - startTime,
                timestamp: new Date().toISOString()
            };
            
            reportHttpsEvent(eventData);
            
            return response;
        };
        
        // Hook OkHttp3 Call.enqueue() (异步请求)
        Call.enqueue.implementation = function(callback) {
            var request = this.request();
            var startTime = Date.now();
            
            // 获取请求信息
            var method = request.method();
            var url = request.url().toString();
            var reqHeaders = {};
            var reqBody = "";
            
            // 提取请求头
            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {
                var name = headers.name(i);
                var value = headers.value(i);
                reqHeaders[name] = value;
            }
            
            // 提取请求体
            try {
                var requestBody = request.body();
                if (requestBody != null) {
                    var buffer = Java.use("okio.Buffer").$new();
                    requestBody.writeTo(buffer);
                    reqBody = buffer.readUtf8();
                    reqBody = truncateContent(reqBody, config.maxBodySize);
                }
            } catch (e) {
                log("Failed to read request body: " + e.message, "warning");
            }
            
            log("Intercepted async request: " + method + " " + url);
            
            // 创建包装的回调
            var Callback = Java.use("okhttp3.Callback");
            var wrappedCallback = Java.registerClass({
                name: "com.frida.WrappedCallback",
                implements: [Callback],
                methods: {
                    onFailure: function(call, e) {
                        var endTime = Date.now();
                        
                        // 上报失败事件
                        var eventData = {
                            id: "okhttp_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
                            script_id: "okhttp_hook",
                            method: method,
                            url: url,
                            req_headers: reqHeaders,
                            req_body: reqBody,
                            res_headers: {},
                            res_body: "Request failed: " + e.getMessage(),
                            status_code: 0,
                            duration_ms: endTime - startTime,
                            timestamp: new Date().toISOString()
                        };
                        
                        reportHttpsEvent(eventData);
                        
                        // 调用原始回调
                        callback.onFailure(call, e);
                    },
                    onResponse: function(call, response) {
                        var endTime = Date.now();
                        
                        // 获取响应信息
                        var statusCode = response.code();
                        var resHeaders = {};
                        var resBody = "";
                        
                        // 提取响应头
                        var responseHeaders = response.headers();
                        for (var i = 0; i < responseHeaders.size(); i++) {
                            var name = responseHeaders.name(i);
                            var value = responseHeaders.value(i);
                            resHeaders[name] = value;
                        }
                        
                        // 提取响应体
                        try {
                            var responseBody = response.body();
                            if (responseBody != null) {
                                var source = responseBody.source();
                                source.request(Java.use("java.lang.Long").MAX_VALUE);
                                var buffer = source.buffer();
                                resBody = buffer.clone().readUtf8();
                                resBody = truncateContent(resBody, config.maxBodySize);
                            }
                        } catch (e) {
                            log("Failed to read response body: " + e.message, "warning");
                        }
                        
                        // 上报事件
                        var eventData = {
                            id: "okhttp_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
                            script_id: "okhttp_hook",
                            method: method,
                            url: url,
                            req_headers: reqHeaders,
                            req_body: reqBody,
                            res_headers: resHeaders,
                            res_body: resBody,
                            status_code: statusCode,
                            duration_ms: endTime - startTime,
                            timestamp: new Date().toISOString()
                        };
                        
                        reportHttpsEvent(eventData);
                        
                        // 调用原始回调
                        callback.onResponse(call, response);
                    }
                }
            });
            
            // 使用包装的回调执行请求
            this.enqueue(wrappedCallback.$new());
        };
        
        log("OkHttp hooks installed successfully");
        
    } catch (e) {
        log("Failed to hook OkHttp: " + e.message, "error");
    }
}

// 主函数
function main() {
    log("Starting OkHttp hook script");
    
    Java.perform(function() {
        try {
            hookOkHttp();
            log("OkHttp hook script initialized successfully");
        } catch (e) {
            log("Failed to initialize OkHttp hook: " + e.message, "error");
        }
    });
}

// 启动脚本
main();

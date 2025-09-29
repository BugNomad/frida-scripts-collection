/**
 * XHR/Fetch 网络请求拦截脚本
 * 拦截 XMLHttpRequest 和 Fetch API 的网络请求并上报到后端
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
        console.log("[XHR Hook] " + message);
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
}

// Hook XMLHttpRequest
function hookXMLHttpRequest() {
    try {
        // 获取原始的 XMLHttpRequest
        var originalXHR = XMLHttpRequest;
        var originalOpen = originalXHR.prototype.open;
        var originalSend = originalXHR.prototype.send;
        var originalSetRequestHeader = originalXHR.prototype.setRequestHeader;
        
        // 重写 XMLHttpRequest
        XMLHttpRequest = function() {
            var xhr = new originalXHR();
            var requestData = {
                method: '',
                url: '',
                headers: {},
                body: '',
                startTime: 0
            };
            
            // Hook open 方法
            xhr.open = function(method, url, async, user, password) {
                requestData.method = method;
                requestData.url = url;
                requestData.startTime = Date.now();
                
                log("XHR open: " + method + " " + url);
                
                return originalOpen.call(this, method, url, async, user, password);
            };
            
            // Hook setRequestHeader 方法
            xhr.setRequestHeader = function(name, value) {
                requestData.headers[name] = value;
                return originalSetRequestHeader.call(this, name, value);
            };
            
            // Hook send 方法
            xhr.send = function(body) {
                requestData.body = body || '';
                
                // 监听响应
                var originalOnReadyStateChange = this.onreadystatechange;
                this.onreadystatechange = function() {
                    if (this.readyState === 4) { // DONE
                        var endTime = Date.now();
                        
                        // 获取响应头
                        var resHeaders = {};
                        try {
                            var headerString = this.getAllResponseHeaders();
                            if (headerString) {
                                var headers = headerString.split('\r\n');
                                for (var i = 0; i < headers.length; i++) {
                                    var header = headers[i];
                                    var colonIndex = header.indexOf(':');
                                    if (colonIndex > 0) {
                                        var name = header.substring(0, colonIndex).trim();
                                        var value = header.substring(colonIndex + 1).trim();
                                        resHeaders[name] = value;
                                    }
                                }
                            }
                        } catch (e) {
                            log("Failed to get response headers: " + e.message, "warning");
                        }
                        
                        // 上报事件
                        var eventData = {
                            id: "xhr_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
                            script_id: "xhr_hook",
                            method: requestData.method,
                            url: requestData.url,
                            req_headers: requestData.headers,
                            req_body: truncateContent(requestData.body, config.maxBodySize),
                            res_headers: resHeaders,
                            res_body: truncateContent(this.responseText, config.maxBodySize),
                            status_code: this.status,
                            duration_ms: endTime - requestData.startTime,
                            timestamp: new Date().toISOString()
                        };
                        
                        reportHttpsEvent(eventData);
                    }
                    
                    // 调用原始的 onreadystatechange
                    if (originalOnReadyStateChange) {
                        originalOnReadyStateChange.call(this);
                    }
                };
                
                return originalSend.call(this, body);
            };
            
            return xhr;
        };
        
        // 复制原始构造函数的属性
        for (var prop in originalXHR) {
            if (originalXHR.hasOwnProperty(prop)) {
                XMLHttpRequest[prop] = originalXHR[prop];
            }
        }
        XMLHttpRequest.prototype = originalXHR.prototype;
        
        log("XMLHttpRequest hooks installed successfully");
        
    } catch (e) {
        log("Failed to hook XMLHttpRequest: " + e.message, "error");
    }
}

// Hook Fetch API
function hookFetch() {
    try {
        if (typeof fetch === 'undefined') {
            log("Fetch API not available", "warning");
            return;
        }
        
        var originalFetch = fetch;
        
        fetch = function(input, init) {
            var startTime = Date.now();
            var url = typeof input === 'string' ? input : input.url;
            var method = (init && init.method) || 'GET';
            var headers = {};
            var body = (init && init.body) || '';
            
            // 提取请求头
            if (init && init.headers) {
                if (init.headers instanceof Headers) {
                    init.headers.forEach(function(value, name) {
                        headers[name] = value;
                    });
                } else if (typeof init.headers === 'object') {
                    for (var name in init.headers) {
                        headers[name] = init.headers[name];
                    }
                }
            }
            
            log("Fetch request: " + method + " " + url);
            
            // 执行原始 fetch
            return originalFetch.call(this, input, init).then(function(response) {
                var endTime = Date.now();
                
                // 克隆响应以避免消费响应体
                var responseClone = response.clone();
                
                // 获取响应头
                var resHeaders = {};
                response.headers.forEach(function(value, name) {
                    resHeaders[name] = value;
                });
                
                // 读取响应体
                responseClone.text().then(function(responseText) {
                    // 上报事件
                    var eventData = {
                        id: "fetch_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
                        script_id: "xhr_hook",
                        method: method,
                        url: url,
                        req_headers: headers,
                        req_body: truncateContent(body, config.maxBodySize),
                        res_headers: resHeaders,
                        res_body: truncateContent(responseText, config.maxBodySize),
                        status_code: response.status,
                        duration_ms: endTime - startTime,
                        timestamp: new Date().toISOString()
                    };
                    
                    reportHttpsEvent(eventData);
                }).catch(function(e) {
                    log("Failed to read fetch response body: " + e.message, "warning");
                });
                
                return response;
            }).catch(function(error) {
                var endTime = Date.now();
                
                // 上报失败事件
                var eventData = {
                    id: "fetch_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
                    script_id: "xhr_hook",
                    method: method,
                    url: url,
                    req_headers: headers,
                    req_body: truncateContent(body, config.maxBodySize),
                    res_headers: {},
                    res_body: "Fetch failed: " + error.message,
                    status_code: 0,
                    duration_ms: endTime - startTime,
                    timestamp: new Date().toISOString()
                };
                
                reportHttpsEvent(eventData);
                
                throw error;
            });
        };
        
        log("Fetch API hooks installed successfully");
        
    } catch (e) {
        log("Failed to hook Fetch API: " + e.message, "error");
    }
}

// 主函数
function main() {
    log("Starting XHR/Fetch hook script");
    
    try {
        hookXMLHttpRequest();
        hookFetch();
        log("XHR/Fetch hook script initialized successfully");
    } catch (e) {
        log("Failed to initialize XHR/Fetch hook: " + e.message, "error");
    }
}

// 启动脚本
main();

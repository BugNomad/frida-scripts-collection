/**
 * URLSession 网络请求拦截脚本 (iOS)
 * 拦截 NSURLSession 的网络请求并上报到后端
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
        console.log("[URLSession Hook] " + message);
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

// 将 NSData 转换为字符串
function nsDataToString(nsData) {
    if (!nsData) return "";
    try {
        var nsString = ObjC.classes.NSString.alloc().initWithData_encoding_(nsData, 4); // NSUTF8StringEncoding = 4
        return nsString ? nsString.toString() : "";
    } catch (e) {
        return "[Binary Data]";
    }
}

// 将 NSDictionary 转换为 JavaScript 对象
function nsDictionaryToObject(nsDict) {
    if (!nsDict) return {};
    
    var result = {};
    var keys = nsDict.allKeys();
    for (var i = 0; i < keys.count(); i++) {
        var key = keys.objectAtIndex_(i).toString();
        var value = nsDict.objectForKey_(key).toString();
        result[key] = value;
    }
    return result;
}

// Hook NSURLSession
function hookNSURLSession() {
    try {
        if (!ObjC.available) {
            log("Objective-C runtime not available", "error");
            return;
        }
        
        // Hook NSURLSessionDataTask
        var NSURLSessionDataTask = ObjC.classes.NSURLSessionDataTask;
        if (!NSURLSessionDataTask) {
            log("NSURLSessionDataTask not found", "error");
            return;
        }
        
        // Hook resume 方法
        var originalResume = NSURLSessionDataTask['- resume'];
        NSURLSessionDataTask['- resume'] = ObjC.implement(originalResume, function(handle, selector) {
            var task = new ObjC.Object(handle);
            var request = task.currentRequest();
            var startTime = Date.now();
            
            if (request) {
                var url = request.URL().absoluteString().toString();
                var method = request.HTTPMethod().toString();
                var headers = nsDictionaryToObject(request.allHTTPHeaderFields());
                var body = "";
                
                // 获取请求体
                var httpBody = request.HTTPBody();
                if (httpBody) {
                    body = nsDataToString(httpBody);
                    body = truncateContent(body, config.maxBodySize);
                }
                
                log("URLSession request: " + method + " " + url);
                
                // 存储请求信息到任务对象
                task.fridaRequestData = {
                    method: method,
                    url: url,
                    headers: headers,
                    body: body,
                    startTime: startTime
                };
            }
            
            // 调用原始方法
            return originalResume(handle, selector);
        });
        
        log("NSURLSessionDataTask hooks installed successfully");
        
        // Hook NSURLSessionDelegate 方法
        var NSURLSessionDelegate = ObjC.protocols.NSURLSessionDelegate;
        if (NSURLSessionDelegate) {
            // Hook didCompleteWithError
            var originalDidComplete = NSURLSessionDelegate['- URLSession:task:didCompleteWithError:'];
            if (originalDidComplete) {
                NSURLSessionDelegate['- URLSession:task:didCompleteWithError:'] = ObjC.implement(originalDidComplete, function(handle, selector, session, task, error) {
                    var taskObj = new ObjC.Object(task);
                    var requestData = taskObj.fridaRequestData;
                    
                    if (requestData) {
                        var endTime = Date.now();
                        var response = taskObj.response();
                        
                        var statusCode = 0;
                        var resHeaders = {};
                        
                        if (response && response.isKindOfClass_(ObjC.classes.NSHTTPURLResponse)) {
                            var httpResponse = new ObjC.Object(response);
                            statusCode = httpResponse.statusCode();
                            resHeaders = nsDictionaryToObject(httpResponse.allHeaderFields());
                        }
                        
                        var resBody = "";
                        if (error) {
                            resBody = "Request failed: " + error.localizedDescription().toString();
                        }
                        
                        // 上报事件
                        var eventData = {
                            id: "urlsession_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
                            script_id: "urlsession_hook",
                            method: requestData.method,
                            url: requestData.url,
                            req_headers: requestData.headers,
                            req_body: requestData.body,
                            res_headers: resHeaders,
                            res_body: resBody,
                            status_code: statusCode,
                            duration_ms: endTime - requestData.startTime,
                            timestamp: new Date().toISOString()
                        };
                        
                        reportHttpsEvent(eventData);
                    }
                    
                    // 调用原始方法
                    return originalDidComplete(handle, selector, session, task, error);
                });
            }
            
            // Hook didReceiveData
            var originalDidReceiveData = NSURLSessionDelegate['- URLSession:dataTask:didReceiveData:'];
            if (originalDidReceiveData) {
                NSURLSessionDelegate['- URLSession:dataTask:didReceiveData:'] = ObjC.implement(originalDidReceiveData, function(handle, selector, session, dataTask, data) {
                    var taskObj = new ObjC.Object(dataTask);
                    var requestData = taskObj.fridaRequestData;
                    
                    if (requestData) {
                        // 累积响应数据
                        if (!requestData.responseData) {
                            requestData.responseData = "";
                        }
                        
                        var dataString = nsDataToString(new ObjC.Object(data));
                        requestData.responseData += dataString;
                        
                        // 限制响应数据大小
                        if (requestData.responseData.length > config.maxBodySize) {
                            requestData.responseData = requestData.responseData.substring(0, config.maxBodySize) + "... [truncated]";
                        }
                    }
                    
                    // 调用原始方法
                    return originalDidReceiveData(handle, selector, session, dataTask, data);
                });
            }
        }
        
        log("NSURLSessionDelegate hooks installed successfully");
        
    } catch (e) {
        log("Failed to hook NSURLSession: " + e.message, "error");
    }
}

// Hook NSURLConnection (旧版 API)
function hookNSURLConnection() {
    try {
        var NSURLConnection = ObjC.classes.NSURLConnection;
        if (!NSURLConnection) {
            log("NSURLConnection not found", "warning");
            return;
        }
        
        // Hook sendSynchronousRequest
        var originalSendSync = NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'];
        if (originalSendSync) {
            NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'] = ObjC.implement(originalSendSync, function(handle, selector, request, response, error) {
                var startTime = Date.now();
                
                var url = request.URL().absoluteString().toString();
                var method = request.HTTPMethod().toString();
                var headers = nsDictionaryToObject(request.allHTTPHeaderFields());
                var body = "";
                
                var httpBody = request.HTTPBody();
                if (httpBody) {
                    body = nsDataToString(httpBody);
                    body = truncateContent(body, config.maxBodySize);
                }
                
                log("NSURLConnection sync request: " + method + " " + url);
                
                // 调用原始方法
                var result = originalSendSync(handle, selector, request, response, error);
                var endTime = Date.now();
                
                // 获取响应信息
                var statusCode = 0;
                var resHeaders = {};
                var resBody = "";
                
                if (response) {
                    var responseObj = new ObjC.Object(Memory.readPointer(response));
                    if (responseObj && responseObj.isKindOfClass_(ObjC.classes.NSHTTPURLResponse)) {
                        statusCode = responseObj.statusCode();
                        resHeaders = nsDictionaryToObject(responseObj.allHeaderFields());
                    }
                }
                
                if (result) {
                    resBody = nsDataToString(new ObjC.Object(result));
                    resBody = truncateContent(resBody, config.maxBodySize);
                }
                
                // 上报事件
                var eventData = {
                    id: "urlconnection_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
                    script_id: "urlsession_hook",
                    method: method,
                    url: url,
                    req_headers: headers,
                    req_body: body,
                    res_headers: resHeaders,
                    res_body: resBody,
                    status_code: statusCode,
                    duration_ms: endTime - startTime,
                    timestamp: new Date().toISOString()
                };
                
                reportHttpsEvent(eventData);
                
                return result;
            });
        }
        
        log("NSURLConnection hooks installed successfully");
        
    } catch (e) {
        log("Failed to hook NSURLConnection: " + e.message, "error");
    }
}

// 主函数
function main() {
    log("Starting URLSession hook script");
    
    if (ObjC.available) {
        try {
            hookNSURLSession();
            hookNSURLConnection();
            log("URLSession hook script initialized successfully");
        } catch (e) {
            log("Failed to initialize URLSession hook: " + e.message, "error");
        }
    } else {
        log("Objective-C runtime not available - this script is for iOS/macOS", "error");
    }
}

// 启动脚本
main();

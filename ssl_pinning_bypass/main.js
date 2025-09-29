/**
 * SSL Pinning 绕过脚本
 * 支持多种 SSL Pinning 实现的绕过
 */

// 环境变量配置
var config = {
    enableLogging: true,
    reportUrl: "http://localhost:8000/api/hooks/https"
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
        console.log("[SSL Bypass] " + message);
    }
}

// Android SSL Pinning 绕过
function bypassAndroidSSLPinning() {
    if (!Java.available) {
        log("Java runtime not available", "warning");
        return;
    }
    
    Java.perform(function() {
        try {
            // 1. 绕过 OkHttp3 CertificatePinner
            try {
                var CertificatePinner = Java.use("okhttp3.CertificatePinner");
                CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
                    log("OkHttp3 CertificatePinner.check() bypassed for: " + hostname);
                    return;
                };
                log("OkHttp3 CertificatePinner bypass enabled");
            } catch (e) {
                log("OkHttp3 CertificatePinner not found: " + e.message, "debug");
            }
            
            // 2. 绕过 Android Network Security Config
            try {
                var NetworkSecurityPolicy = Java.use("android.security.NetworkSecurityPolicy");
                NetworkSecurityPolicy.getInstance.implementation = function() {
                    log("NetworkSecurityPolicy.getInstance() called");
                    var policy = this.getInstance();
                    
                    // Hook isCertificateTransparencyVerificationRequired
                    policy.isCertificateTransparencyVerificationRequired.implementation = function(hostname) {
                        log("NetworkSecurityPolicy.isCertificateTransparencyVerificationRequired() bypassed for: " + hostname);
                        return false;
                    };
                    
                    return policy;
                };
                log("Android Network Security Config bypass enabled");
            } catch (e) {
                log("NetworkSecurityPolicy not found: " + e.message, "debug");
            }
            
            // 3. 绕过 HttpsURLConnection
            try {
                var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
                    log("HttpsURLConnection.setDefaultHostnameVerifier() bypassed");
                    return;
                };
                
                HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
                    log("HttpsURLConnection.setHostnameVerifier() bypassed");
                    return;
                };
                
                log("HttpsURLConnection hostname verification bypass enabled");
            } catch (e) {
                log("HttpsURLConnection not found: " + e.message, "debug");
            }
            
            // 4. 绕过 TrustManager
            try {
                var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                var SSLContext = Java.use("javax.net.ssl.SSLContext");
                
                // 创建自定义 TrustManager
                var TrustManager = Java.registerClass({
                    name: "com.frida.TrustManager",
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {
                            log("TrustManager.checkClientTrusted() bypassed");
                        },
                        checkServerTrusted: function(chain, authType) {
                            log("TrustManager.checkServerTrusted() bypassed");
                        },
                        getAcceptedIssuers: function() {
                            return [];
                        }
                    }
                });
                
                // Hook SSLContext.init
                SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(keyManagers, trustManagers, secureRandom) {
                    log("SSLContext.init() called - replacing TrustManager");
                    var customTrustManager = TrustManager.$new();
                    return this.init(keyManagers, [customTrustManager], secureRandom);
                };
                
                log("TrustManager bypass enabled");
            } catch (e) {
                log("TrustManager bypass failed: " + e.message, "warning");
            }
            
            // 5. 绕过 Conscrypt (Google Play Services)
            try {
                var ConscryptFileDescriptorSocket = Java.use("com.google.android.gms.org.conscrypt.ConscryptFileDescriptorSocket");
                ConscryptFileDescriptorSocket.verifyCertificateChain.implementation = function(certChain, authMethod) {
                    log("Conscrypt certificate verification bypassed");
                    return;
                };
                log("Conscrypt SSL verification bypass enabled");
            } catch (e) {
                log("Conscrypt not found: " + e.message, "debug");
            }
            
            // 6. 绕过 Apache HTTP Client
            try {
                var DefaultHttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
                DefaultHttpClient.execute.overload("org.apache.http.client.methods.HttpUriRequest").implementation = function(request) {
                    log("Apache DefaultHttpClient.execute() called");
                    return this.execute(request);
                };
                log("Apache HTTP Client monitoring enabled");
            } catch (e) {
                log("Apache HTTP Client not found: " + e.message, "debug");
            }
            
        } catch (e) {
            log("Error in SSL Pinning bypass: " + e.message, "error");
        }
    });
}

// iOS SSL Pinning 绕过
function bypassiOSSSLPinning() {
    if (!ObjC.available) {
        log("Objective-C runtime not available", "warning");
        return;
    }
    
    try {
        // 1. 绕过 NSURLSession
        var NSURLSession = ObjC.classes.NSURLSession;
        if (NSURLSession) {
            var originalSessionWithConfiguration = NSURLSession['+ sessionWithConfiguration:'];
            NSURLSession['+ sessionWithConfiguration:'] = ObjC.implement(originalSessionWithConfiguration, function(handle, selector, configuration) {
                log("NSURLSession sessionWithConfiguration called");
                var session = originalSessionWithConfiguration(handle, selector, configuration);
                return session;
            });
            log("NSURLSession SSL bypass enabled");
        }
        
        // 2. 绕过 CFNetwork
        var CFNetworkModule = Module.findExportByName("CFNetwork", "CFNetworkExecuteProxyAutoConfigurationURL");
        if (CFNetworkModule) {
            log("CFNetwork module found");
        }
        
        // 3. 绕过 Security Framework
        var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                log("SecTrustEvaluate called - bypassing");
                Memory.writeU8(result, 1); // kSecTrustResultProceed
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
            log("SecTrustEvaluate bypass enabled");
        }
        
    } catch (e) {
        log("Error in iOS SSL Pinning bypass: " + e.message, "error");
    }
}

// 主函数
function main() {
    log("Starting SSL Pinning bypass script");
    
    // 检测平台并应用相应的绕过
    if (Java.available) {
        log("Android platform detected");
        bypassAndroidSSLPinning();
    } else if (ObjC.available) {
        log("iOS platform detected");
        bypassiOSSSLPinning();
    } else {
        log("Unknown platform", "warning");
    }
    
    log("SSL Pinning bypass script initialized");
}

// 启动脚本
main();

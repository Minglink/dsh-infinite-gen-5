// Android capability taxonomy: which permissions, framework calls, fields, strings and base classes point at which
// capability. Pure data plus small matchers; the APK analysis feeds it what the DEX and the manifest contain.
// A hit is a LEAD about what code can do, never a verdict about intent: ordinary apps use most of these APIs.
// Rules are validated at import, so a typo in this table fails the first test run instead of silently never matching.

export const STRENGTH = Object.freeze({ weak: 1, moderate: 2, strong: 3 });
export const CATEGORIES = Object.freeze({
  'sms-send': 'Sends SMS/MMS', 'sms-read': 'Reads or intercepts SMS', telephony: 'Reads telephony identity or controls calls', contacts: 'Reads contacts or call log', location: 'Reads location',
  'audio-record': 'Records audio', camera: 'Uses the camera', 'screen-capture': 'Captures the screen', accessibility: 'Accessibility service control (reads UI, performs gestures)',
  overlay: 'Draws over other apps', 'device-admin': 'Device administration (lock, wipe, password)', 'notification-access': 'Reads notifications', vpn: 'VPN service (traffic interception)',
  'input-method': 'Input method (key input)', 'dynamic-code-loading': 'Loads code at run time', 'native-code': 'Loads native libraries', exec: 'Runs processes or shell commands',
  reflection: 'Reflection', crypto: 'Cryptography', network: 'Network access', 'tls-weakening': 'Replaces TLS certificate or host verification', webview: 'WebView with script bridge or file access',
  'package-install': 'Installs or hides packages', 'app-enumeration': 'Lists installed apps or running tasks', clipboard: 'Reads or writes the clipboard', persistence: 'Starts at boot or reschedules itself',
  'anti-debug': 'Detects a debugger', 'emulator-detection': 'Inspects device model to detect emulators', 'root-detection': 'Looks for root tools', 'hook-detection': 'Looks for instrumentation frameworks',
  'device-identity': 'Collects device identifiers', 'system-settings': 'Changes system settings', storage: 'Broad file storage access', 'c2-channel': 'Messaging or paste services often used as control channels',
  'screen-lock': 'Disables or controls the lock screen', biometric: 'Uses biometrics',
  'packer-wrapper': 'Commercial APK wrapper or DEX protector stub',
  'cross-platform': 'Cross-platform runtime payload (Flutter, React Native/Hermes, ArkTS)',
});

const P = 'android.permission.';
const permission = (name, category, level, note) => [P + name, { category, level, note }];
/** Manifest permissions. level: normal | dangerous | special | signature (how Android gates it). */
export const PERMISSIONS = new Map([
  permission('SEND_SMS', 'sms-send', 'dangerous'), permission('RECEIVE_SMS', 'sms-read', 'dangerous'), permission('READ_SMS', 'sms-read', 'dangerous'), permission('RECEIVE_MMS', 'sms-read', 'dangerous'),
  permission('RECEIVE_WAP_PUSH', 'sms-read', 'dangerous'), permission('WRITE_SMS', 'sms-send', 'signature'),
  permission('READ_CONTACTS', 'contacts', 'dangerous'), permission('WRITE_CONTACTS', 'contacts', 'dangerous'), permission('GET_ACCOUNTS', 'contacts', 'dangerous'),
  permission('READ_CALL_LOG', 'contacts', 'dangerous'), permission('WRITE_CALL_LOG', 'contacts', 'dangerous'),
  permission('READ_PHONE_STATE', 'telephony', 'dangerous'), permission('READ_PHONE_NUMBERS', 'telephony', 'dangerous'), permission('CALL_PHONE', 'telephony', 'dangerous'),
  permission('ANSWER_PHONE_CALLS', 'telephony', 'dangerous'), permission('PROCESS_OUTGOING_CALLS', 'telephony', 'dangerous'), permission('MODIFY_PHONE_STATE', 'telephony', 'signature'),
  permission('ACCESS_FINE_LOCATION', 'location', 'dangerous'), permission('ACCESS_COARSE_LOCATION', 'location', 'dangerous'), permission('ACCESS_BACKGROUND_LOCATION', 'location', 'dangerous'),
  permission('RECORD_AUDIO', 'audio-record', 'dangerous'), permission('CAMERA', 'camera', 'dangerous'),
  permission('READ_EXTERNAL_STORAGE', 'storage', 'dangerous'), permission('WRITE_EXTERNAL_STORAGE', 'storage', 'dangerous'), permission('MANAGE_EXTERNAL_STORAGE', 'storage', 'special'),
  permission('SYSTEM_ALERT_WINDOW', 'overlay', 'special'), permission('BIND_ACCESSIBILITY_SERVICE', 'accessibility', 'signature'), permission('BIND_DEVICE_ADMIN', 'device-admin', 'signature'),
  permission('BIND_NOTIFICATION_LISTENER_SERVICE', 'notification-access', 'signature'), permission('BIND_VPN_SERVICE', 'vpn', 'signature'), permission('BIND_INPUT_METHOD', 'input-method', 'signature'),
  permission('REQUEST_INSTALL_PACKAGES', 'package-install', 'special'), permission('INSTALL_PACKAGES', 'package-install', 'signature'), permission('DELETE_PACKAGES', 'package-install', 'signature'),
  permission('REQUEST_DELETE_PACKAGES', 'package-install', 'normal'), permission('QUERY_ALL_PACKAGES', 'app-enumeration', 'special'), permission('GET_TASKS', 'app-enumeration', 'normal'),
  permission('PACKAGE_USAGE_STATS', 'app-enumeration', 'special'), permission('RECEIVE_BOOT_COMPLETED', 'persistence', 'normal'), permission('REQUEST_IGNORE_BATTERY_OPTIMIZATIONS', 'persistence', 'normal'),
  permission('INTERNET', 'network', 'normal'), permission('ACCESS_NETWORK_STATE', 'network', 'normal'), permission('ACCESS_WIFI_STATE', 'network', 'normal'), permission('CHANGE_WIFI_STATE', 'network', 'normal'),
  permission('WRITE_SETTINGS', 'system-settings', 'special'), permission('WRITE_SECURE_SETTINGS', 'system-settings', 'signature'), permission('DISABLE_KEYGUARD', 'screen-lock', 'normal'),
  permission('USE_BIOMETRIC', 'biometric', 'normal'), permission('USE_FINGERPRINT', 'biometric', 'normal'), permission('READ_LOGS', 'device-identity', 'signature'),
]);

const api = (id, category, strength, cls, names, note) => ({ id, category, strength, cls, names, note });
const apiPrefix = (id, category, strength, prefix, note) => ({ id, category, strength, prefix, note });
const SMS = 'Landroid/telephony/SmsManager;', DPM = 'Landroid/app/admin/DevicePolicyManager;', PM = 'Landroid/content/pm/PackageManager;', HUC = 'Ljavax/net/ssl/HttpsURLConnection;';
/** Framework method calls. ``names`` omitted = any method of the class. */
export const API_RULES = [
  api('sms.send', 'sms-send', 3, SMS, ['sendTextMessage', 'sendMultipartTextMessage', 'sendDataMessage', 'sendTextMessageWithoutPersisting']),
  api('sms.send-legacy', 'sms-send', 3, 'Landroid/telephony/gsm/SmsManager;', ['sendTextMessage', 'sendMultipartTextMessage', 'sendDataMessage']),
  api('sms.parse', 'sms-read', 2, 'Landroid/telephony/SmsMessage;', ['createFromPdu', 'getMessageBody', 'getOriginatingAddress', 'getDisplayMessageBody']),
  api('telephony.identity', 'device-identity', 2, 'Landroid/telephony/TelephonyManager;', ['getDeviceId', 'getImei', 'getMeid', 'getSubscriberId', 'getLine1Number', 'getSimSerialNumber']),
  api('telephony.operator', 'telephony', 1, 'Landroid/telephony/TelephonyManager;', ['getNetworkOperator', 'getSimOperator', 'getNetworkCountryIso', 'getSimCountryIso']),
  api('telecom.call', 'telephony', 2, 'Landroid/telecom/TelecomManager;', ['placeCall', 'endCall', 'acceptRingingCall']),
  api('location.manager', 'location', 2, 'Landroid/location/LocationManager;', ['requestLocationUpdates', 'getLastKnownLocation', 'requestSingleUpdate']),
  api('location.fused', 'location', 2, 'Lcom/google/android/gms/location/FusedLocationProviderClient;', ['getLastLocation', 'requestLocationUpdates', 'getCurrentLocation']),
  api('audio.record', 'audio-record', 2, 'Landroid/media/AudioRecord;', ['<init>', 'startRecording']),
  api('audio.mediarecorder', 'audio-record', 2, 'Landroid/media/MediaRecorder;', ['setAudioSource', 'start']),
  api('camera.legacy', 'camera', 2, 'Landroid/hardware/Camera;', ['open', 'takePicture']), api('camera.camera2', 'camera', 2, 'Landroid/hardware/camera2/CameraManager;', ['openCamera']),
  api('screen.projection', 'screen-capture', 3, 'Landroid/media/projection/MediaProjectionManager;', ['createScreenCaptureIntent', 'getMediaProjection']),
  api('screen.display', 'screen-capture', 3, 'Landroid/media/projection/MediaProjection;', ['createVirtualDisplay']),
  api('a11y.global', 'accessibility', 3, 'Landroid/accessibilityservice/AccessibilityService;', ['performGlobalAction', 'dispatchGesture', 'getRootInActiveWindow', 'findFocus']),
  api('a11y.node', 'accessibility', 3, 'Landroid/view/accessibility/AccessibilityNodeInfo;', ['performAction', 'findAccessibilityNodeInfosByText', 'findAccessibilityNodeInfosByViewId']),
  api('admin.policy', 'device-admin', 3, DPM, ['lockNow', 'wipeData', 'resetPassword', 'setPasswordQuality', 'setCameraDisabled', 'setKeyguardDisabledFeatures', 'setDeviceOwnerLockScreenInfo']),
  api('admin.component', 'device-admin', 1, DPM, ['isAdminActive', 'getActiveAdmins']),
  api('overlay.window', 'overlay', 1, 'Landroid/view/WindowManager;', ['addView'], 'Many apps add views; only meaningful with SYSTEM_ALERT_WINDOW'),
  api('dcl.dexclassloader', 'dynamic-code-loading', 3, 'Ldalvik/system/DexClassLoader;', ['<init>']),
  api('dcl.inmemory', 'dynamic-code-loading', 3, 'Ldalvik/system/InMemoryDexClassLoader;', ['<init>']),
  api('dcl.pathclassloader', 'dynamic-code-loading', 2, 'Ldalvik/system/PathClassLoader;', ['<init>']),
  api('dcl.basedex', 'dynamic-code-loading', 2, 'Ldalvik/system/BaseDexClassLoader;', ['<init>']),
  api('dcl.dexfile', 'dynamic-code-loading', 3, 'Ldalvik/system/DexFile;', ['loadDex', '<init>', 'loadClass']),
  api('native.system', 'native-code', 1, 'Ljava/lang/System;', ['load', 'loadLibrary']), api('native.runtime', 'native-code', 1, 'Ljava/lang/Runtime;', ['load', 'loadLibrary']),
  api('exec.runtime', 'exec', 3, 'Ljava/lang/Runtime;', ['exec']), api('exec.builder', 'exec', 3, 'Ljava/lang/ProcessBuilder;', ['start']),
  api('reflect.invoke', 'reflection', 1, 'Ljava/lang/reflect/Method;', ['invoke']),
  api('reflect.lookup', 'reflection', 1, 'Ljava/lang/Class;', ['forName', 'getMethod', 'getDeclaredMethod', 'getDeclaredField', 'getDeclaredConstructor']),
  api('crypto.cipher', 'crypto', 1, 'Ljavax/crypto/Cipher;', ['getInstance', 'doFinal', 'init']), api('crypto.key', 'crypto', 1, 'Ljavax/crypto/spec/SecretKeySpec;', ['<init>']),
  api('crypto.iv', 'crypto', 1, 'Ljavax/crypto/spec/IvParameterSpec;', ['<init>']), api('crypto.digest', 'crypto', 1, 'Ljava/security/MessageDigest;', ['getInstance', 'digest']),
  api('crypto.keyinfo', 'crypto', 2, 'Landroid/security/keystore/KeyInfo;', ['isInsideSecurityHardware', 'getSecurityLevel', 'isUserAuthenticationRequired']),
  api('crypto.keystore', 'crypto', 1, 'Ljava/security/KeyStore;', ['getInstance', 'load', 'getEntry']),
  api('net.url', 'network', 1, 'Ljava/net/URL;', ['openConnection', 'openStream']), api('net.http', 'network', 1, 'Ljava/net/HttpURLConnection;', ['connect', 'getInputStream', 'getOutputStream', 'getResponseCode']),
  api('net.https', 'network', 1, HUC, ['connect', 'getInputStream', 'getOutputStream']), api('net.socket', 'network', 2, 'Ljava/net/Socket;', ['<init>', 'connect']),
  api('net.datagram', 'network', 2, 'Ljava/net/DatagramSocket;', ['send', 'connect']), api('net.okhttp', 'network', 1, 'Lokhttp3/OkHttpClient;', ['newCall']),
  api('net.apache', 'network', 1, 'Lorg/apache/http/impl/client/DefaultHttpClient;', ['execute']), api('net.websocket', 'network', 2, 'Lokhttp3/OkHttpClient;', ['newWebSocket']),
  api('tls.hostname', 'tls-weakening', 3, HUC, ['setDefaultHostnameVerifier', 'setHostnameVerifier']), api('tls.factory', 'tls-weakening', 2, HUC, ['setDefaultSSLSocketFactory', 'setSSLSocketFactory']),
  api('tls.context', 'tls-weakening', 2, 'Ljavax/net/ssl/SSLContext;', ['init']),
  api('web.bridge', 'webview', 2, 'Landroid/webkit/WebView;', ['addJavascriptInterface']), api('web.eval', 'webview', 1, 'Landroid/webkit/WebView;', ['evaluateJavascript', 'loadUrl', 'loadData', 'loadDataWithBaseURL']),
  api('web.filesettings', 'webview', 2, 'Landroid/webkit/WebSettings;', ['setAllowFileAccessFromFileURLs', 'setAllowUniversalAccessFromFileURLs']),
  api('pkg.installer', 'package-install', 3, 'Landroid/content/pm/PackageInstaller;', ['createSession', 'openSession']), api('pkg.install-legacy', 'package-install', 3, PM, ['installPackage']),
  api('pkg.hide', 'package-install', 2, PM, ['setComponentEnabledSetting'], 'Disabling its own launcher component hides the icon'),
  api('pkg.enumerate', 'app-enumeration', 1, PM, ['getInstalledPackages', 'getInstalledApplications', 'queryIntentActivities', 'getPackageInfo']),
  api('pkg.tasks', 'app-enumeration', 2, 'Landroid/app/ActivityManager;', ['getRunningTasks', 'getRunningAppProcesses', 'getRecentTasks']),
  api('pkg.usage', 'app-enumeration', 2, 'Landroid/app/usage/UsageStatsManager;', ['queryUsageStats', 'queryEvents']),
  api('clip.new', 'clipboard', 2, 'Landroid/content/ClipboardManager;', ['getPrimaryClip', 'setPrimaryClip', 'addPrimaryClipChangedListener']),
  api('clip.old', 'clipboard', 2, 'Landroid/text/ClipboardManager;', ['getText', 'setText']),
  api('persist.alarm', 'persistence', 1, 'Landroid/app/AlarmManager;', ['setExact', 'setRepeating', 'setExactAndAllowWhileIdle', 'setAndAllowWhileIdle', 'setInexactRepeating']),
  api('persist.job', 'persistence', 1, 'Landroid/app/job/JobScheduler;', ['schedule']),
  api('anti.debug', 'anti-debug', 2, 'Landroid/os/Debug;', ['isDebuggerConnected', 'waitingForDebugger']),
  api('id.settings', 'device-identity', 1, 'Landroid/provider/Settings$Secure;', ['getString']), api('id.wifi', 'device-identity', 1, 'Landroid/net/wifi/WifiInfo;', ['getMacAddress', 'getSSID', 'getBSSID']),
  api('settings.write', 'system-settings', 2, 'Landroid/provider/Settings$System;', ['putInt', 'putString']), api('settings.secure-write', 'system-settings', 3, 'Landroid/provider/Settings$Secure;', ['putInt', 'putString']),
  api('lock.keyguard', 'screen-lock', 2, 'Landroid/app/KeyguardManager;', ['inKeyguardRestrictedInputMode', 'isKeyguardLocked', 'requestDismissKeyguard']),
  api('bio.prompt', 'biometric', 1, 'Landroid/hardware/biometrics/BiometricPrompt;', ['authenticate']),
  apiPrefix('vpn.service', 'vpn', 2, 'Landroid/net/VpnService', 'Builder / protect / prepare'),
];

const field = (id, category, strength, cls, names) => ({ id, category, strength, cls, names });
/** Static field reads (device model strings are how emulator checks work). */
export const FIELD_RULES = [field('build.model', 'emulator-detection', 2, 'Landroid/os/Build;', ['FINGERPRINT', 'MODEL', 'MANUFACTURER', 'BRAND', 'DEVICE', 'PRODUCT', 'HARDWARE', 'BOARD'])];

const string = (id, category, strength, pattern, note) => ({ id, category, strength, pattern, note });
/** Patterns over DEX string constants (and native library names). */
export const STRING_RULES = [
  string('str.sms-uri', 'sms-read', 2, /^content:\/\/(sms|mms|mms-sms)(\/|$)/i), string('str.contacts-uri', 'contacts', 2, /^content:\/\/(com\.android\.contacts|contacts|call_log)(\/|$)/i),
  string('str.su', 'root-detection', 2, /(^|\/)(su|busybox|magisk)$|Superuser\.apk|com\.topjohnwu\.magisk|eu\.chainfire\.supersu|com\.noshufou\.android\.su/i, 'Paths and package names root checks (and root tools) use'),
  string('str.frida', 'hook-detection', 3, /frida(-server|-gadget|-agent)?\b|re\.frida\.server|gum-js-loop|LIBFRIDA/i), string('str.xposed', 'hook-detection', 2, /de\.robv\.android\.xposed|XposedBridge|com\.saurik\.substrate/),
  string('str.emulator', 'emulator-detection', 2, /\b(goldfish|ranchu|vbox86|genymotion|nox|bluestacks|ttVM_Hdragon)\b|generic_x86|google_sdk|sdk_gphone/i),
  string('str.tracerpid', 'anti-debug', 3, /TracerPid|\/proc\/self\/(status|maps|mem)|\/proc\/\d+\/(status|maps)/),
  string('str.telegram-bot', 'c2-channel', 2, /api\.telegram\.org\/bot[0-9]+:|api\.telegram\.org\/bot%s/i), string('str.discord-webhook', 'c2-channel', 2, /discord(app)?\.com\/api\/webhooks\//i),
  string('str.paste', 'c2-channel', 1, /\b(pastebin\.com\/raw|paste\.ee\/r|raw\.githubusercontent\.com|gist\.githubusercontent\.com)\b/i),
  string('str.shell', 'exec', 2, /^(\/system\/(x?bin)\/)?(sh|su)( -c)?$|^(chmod|chown|mount|pm install|pm uninstall|am start|am broadcast|settings put|input (tap|swipe|text))\b/),
  string('str.packer-wrapper', 'packer-wrapper', 3, /\b(?:libSecShell(?:_[a-z0-9]+)?|libDexHelper(?:_[a-z0-9]+)?|libjiagu(?:_[a-z0-9]+)?|libshell[ax]?(?:_[a-z0-9]+)?|TxAppEntry|libexecmain|libexec(?:_[a-z0-9]+)?\.so|libnesec(?:_[a-z0-9]+)?|StubApp)\b/, 'Commercial APK wrapper library or stub entry'),
  string('str.cross-platform-flutter', 'cross-platform', 2, /\b(libapp\.so|libflutter\.so|_kDartVmSnapshotInstructions|_kDartIsolateSnapshotInstructions|flutter_assets)\b/, 'Flutter AOT runtime markers'),
  string('str.cross-platform-rn', 'cross-platform', 2, /\b(index\.android\.bundle|libhermes\.so|libreactnativejni\.so)\b/, 'React Native / Hermes bundle markers'),
  string('str.cross-platform-arkts', 'cross-platform', 2, /\b(modules\.abc|libark_jsruntime\.so)\b/, 'ArkTS / HarmonyOS bytecode markers'),
  string('str.jni-registernatives', 'native-code', 2, /\bRegisterNatives\b/, 'JNI dynamic registration symbol'),
];

const base = (id, category, strength, superclass) => ({ id, category, strength, superclass });
/** Capabilities implied by extending a framework class: the manifest declares them, the DEX implements them. */
export const SUPERCLASS_RULES = [
  base('base.a11y', 'accessibility', 3, 'Landroid/accessibilityservice/AccessibilityService;'), base('base.admin', 'device-admin', 3, 'Landroid/app/admin/DeviceAdminReceiver;'),
  base('base.notify', 'notification-access', 3, 'Landroid/service/notification/NotificationListenerService;'), base('base.vpn', 'vpn', 3, 'Landroid/net/VpnService;'),
  base('base.ime', 'input-method', 3, 'Landroid/inputmethodservice/InputMethodService;'), base('base.call', 'telephony', 2, 'Landroid/telecom/CallScreeningService;'),
  base('base.incall', 'telephony', 2, 'Landroid/telecom/InCallService;'),
];
/** Interfaces whose implementation in app code usually means a custom (often disabled) TLS check. */
export const INTERFACE_RULES = [
  { id: 'iface.trustmanager', category: 'tls-weakening', strength: 2, interface: 'Ljavax/net/ssl/X509TrustManager;' },
  { id: 'iface.hostname', category: 'tls-weakening', strength: 2, interface: 'Ljavax/net/ssl/HostnameVerifier;' },
];

/**
 * Category combinations worth a human's attention. ``requires`` are categories; a chain with ``either`` needs one of
 * each listed group. Reported as patterns: the match is by capability, so it says what the app CAN do.
 */
export const CHAINS = [
  { id: 'chain.remote-code', strength: 3, requires: ['dynamic-code-loading', 'network'], description: 'Can fetch data over the network and load code at run time' },
  { id: 'chain.packed-loader', strength: 3, requires: ['dynamic-code-loading', 'crypto'], description: 'Decrypts and loads code at run time (typical of packers and droppers)' },
  { id: 'chain.sms-exfiltration', strength: 3, requires: ['sms-read', 'network'], description: 'Can read SMS and reach the network' },
  { id: 'chain.sms-fraud', strength: 3, requires: ['sms-send', 'sms-read'], description: 'Can read and send SMS (interception plus premium or forwarding abuse)' },
  { id: 'chain.overlay-takeover', strength: 3, requires: ['overlay', 'accessibility'], description: 'Can draw over apps and drive the UI (credential theft and remote-control pattern)' },
  { id: 'chain.remote-control', strength: 3, requires: ['accessibility', 'screen-capture', 'network'], description: 'Can read and operate the screen and reach the network' },
  { id: 'chain.audio-spy', strength: 3, requires: ['audio-record', 'network'], description: 'Can record audio and reach the network' },
  { id: 'chain.camera-spy', strength: 2, requires: ['camera', 'network'], description: 'Can use the camera and reach the network' },
  { id: 'chain.location-tracking', strength: 2, requires: ['location', 'network', 'persistence'], description: 'Can track location in the background and report it' },
  { id: 'chain.contacts-exfiltration', strength: 2, requires: ['contacts', 'network'], description: 'Can read contacts or call logs and reach the network' },
  { id: 'chain.clipboard-hijack', strength: 2, requires: ['clipboard', 'network'], description: 'Can read or replace clipboard content and reach the network' },
  { id: 'chain.hidden-resident', strength: 2, requires: ['persistence', 'package-install'], description: 'Starts itself and can hide or install packages' },
  { id: 'chain.shell-root', strength: 2, requires: ['exec', 'root-detection'], description: 'Runs commands and works with root tools' },
  { id: 'chain.evasion', strength: 2, requires: [['anti-debug', 'emulator-detection', 'hook-detection'], ['dynamic-code-loading', 'native-code', 'reflection']], description: 'Checks for analysis environments and also loads code indirectly' },
  { id: 'chain.tls-network', strength: 2, requires: ['tls-weakening', 'network'], description: 'Replaces certificate or host checks and uses the network' },
  { id: 'chain.device-lock', strength: 3, requires: ['device-admin', 'screen-lock'], description: 'Device administration with lock-screen control (lockscreen/ransom pattern)' },
  { id: 'chain.channel-c2', strength: 2, requires: ['c2-channel', 'network'], description: 'Embeds a messaging or paste endpoint commonly used as a control channel' },
];

// ---- validation ----------------------------------------------------------------------------------------------------

const DESCRIPTOR = /^L[A-Za-z0-9_$/]+;$/, METHOD_NAME = /^(<init>|<clinit>|[A-Za-z_][A-Za-z0-9_$]*)$/;
/** Throws listing every inconsistency in a rule set (exported so the tests can feed it broken tables). */
export function validateRules({ API_RULES, FIELD_RULES, STRING_RULES, SUPERCLASS_RULES, INTERFACE_RULES, PERMISSIONS, CHAINS }) {
  const ids = new Set(), problems = [];
  const check = (condition, message) => { if (!condition) problems.push(message); };
  const known = category => Object.hasOwn(CATEGORIES, category);
  const all = [...API_RULES, ...FIELD_RULES, ...STRING_RULES, ...SUPERCLASS_RULES, ...INTERFACE_RULES];
  for (const rule of all) {
    check(typeof rule.id === 'string' && !ids.has(rule.id), `duplicate or missing rule id ${rule.id}`); ids.add(rule.id);
    check(known(rule.category), `${rule.id}: unknown category ${rule.category}`); check(Object.values(STRENGTH).includes(rule.strength), `${rule.id}: strength ${rule.strength}`);
    if ('cls' in rule) check(DESCRIPTOR.test(rule.cls), `${rule.id}: bad class ${rule.cls}`);
    if ('prefix' in rule) check(/^L[A-Za-z0-9_$/]+$/.test(rule.prefix), `${rule.id}: bad prefix`);
    if ('names' in rule && rule.names) { check(rule.names.length > 0, `${rule.id}: empty names`); for (const name of rule.names) check(METHOD_NAME.test(name), `${rule.id}: bad name ${name}`); check(new Set(rule.names).size === rule.names.length, `${rule.id}: repeated name`); }
    if ('pattern' in rule) check(rule.pattern instanceof RegExp && !rule.pattern.global && !rule.pattern.sticky, `${rule.id}: pattern must be a non-global RegExp`);
    if ('superclass' in rule) check(DESCRIPTOR.test(rule.superclass), `${rule.id}: bad superclass`);
    if ('interface' in rule) check(DESCRIPTOR.test(rule.interface), `${rule.id}: bad interface`);
  }
  for (const [name, entry] of PERMISSIONS) {
    check(/^[A-Za-z0-9_.]+$/.test(name), `permission ${name}`); check(known(entry.category), `${name}: unknown category ${entry.category}`);
    check(['normal', 'dangerous', 'special', 'signature'].includes(entry.level), `${name}: level ${entry.level}`);
  }
  for (const chain of CHAINS) {
    check(!ids.has(chain.id), `chain id clashes ${chain.id}`); ids.add(chain.id); check(chain.requires.length >= 2, `${chain.id}: needs two requirements`);
    for (const group of chain.requires) for (const category of [group].flat()) check(known(category), `${chain.id}: unknown category ${category}`);
    check(Object.values(STRENGTH).includes(chain.strength), `${chain.id}: strength`);
  }
  if (problems.length) throw new Error('apk_rules.js is inconsistent:\n  ' + problems.join('\n  '));
}
validateRules({ API_RULES, FIELD_RULES, STRING_RULES, SUPERCLASS_RULES, INTERFACE_RULES, PERMISSIONS, CHAINS });

// ---- matchers ------------------------------------------------------------------------------------------------------

const exact = new Map(), prefixes = [];
for (const rule of API_RULES) {
  if (rule.prefix) prefixes.push(rule); else { if (!exact.has(rule.cls)) exact.set(rule.cls, []); exact.get(rule.cls).push(rule); }
}
const fieldIndex = new Map();
for (const rule of FIELD_RULES) { if (!fieldIndex.has(rule.cls)) fieldIndex.set(rule.cls, []); fieldIndex.get(rule.cls).push(rule); }
const nameMatches = (rule, name) => !rule.names || rule.names.includes(name);

/** Rules matching a call to ``cls->name``. */
export function classifyApi(cls, name) {
  const hits = [];
  for (const rule of exact.get(cls) ?? []) if (nameMatches(rule, name)) hits.push(rule);
  for (const rule of prefixes) if (cls.startsWith(rule.prefix)) hits.push(rule);
  return hits;
}
export function classifyField(cls, name) { return (fieldIndex.get(cls) ?? []).filter(rule => nameMatches(rule, name)); }
const MAX_STRING = 512;
export function classifyString(text) { return typeof text !== 'string' || text.length === 0 || text.length > MAX_STRING ? [] : STRING_RULES.filter(rule => rule.pattern.test(text)); }
export function classifySuperclass(type) { return SUPERCLASS_RULES.filter(rule => rule.superclass === type); }
export function classifyInterface(type) { return INTERFACE_RULES.filter(rule => rule.interface === type); }
export function classifyPermission(name) {
  const known = PERMISSIONS.get(name);
  if (known) return { name, ...known, known: true };
  return { name, category: null, level: name.startsWith(P) ? 'unlisted' : 'custom', note: null, known: false };
}

/**
 * Chains satisfied by a set of categories. ``classCategories`` (optional) is an iterable of per-class sets: a chain whose
 * requirements are all met inside ONE class is reported with ``scope: 'class'`` (stronger evidence, same code) and
 * the class names; otherwise ``scope: 'app'``.
 */
export function evaluateChains(appCategories, classCategories = []) {
  const has = (set, requirement) => [requirement].flat().some(category => set.has(category));
  const out = [];
  for (const chain of CHAINS) {
    if (!chain.requires.every(requirement => has(appCategories, requirement))) continue;
    const classes = [];
    for (const [name, set] of classCategories) if (chain.requires.every(requirement => has(set, requirement))) classes.push(name);
    out.push({ id: chain.id, strength: chain.strength, description: chain.description, scope: classes.length ? 'class' : 'app', classes: classes.slice(0, 20), classCount: classes.length });
  }
  return out;
}

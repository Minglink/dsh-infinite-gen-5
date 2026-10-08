// IG5 SDK bridge: no Qt, no network socket, copied bounded callback records.
// Built against the pinned official SDK. Host approval is outside this bridge.
#include <Windows.h>
#include <sddl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <regex>
#include "_plugins.h"
#include "_dbgfunctions.h"
#include "jansson/jansson.h"

static HANDLE pipeHandle = INVALID_HANDLE_VALUE, threadHandle = nullptr;
static volatile LONG ending = 0;
static CRITICAL_SECTION eventLock;
static json_t* ring[256] = {};
static unsigned long long eventSeq = 0;
static int pluginHandle = 0;

static void str(json_t* obj, const char* key, const char* value) { json_object_set_new(obj, key, json_string(value ? value : "")); }
static void num(json_t* obj, const char* key, unsigned long long value) { json_object_set_new(obj, key, json_integer((json_int_t)value)); }
static void flag(json_t* obj, const char* key, bool value) { json_object_set_new(obj, key, json_boolean(value)); }
static void address(json_t* obj, const char* key, unsigned long long value) { char text[32]; std::snprintf(text, sizeof(text), "0x%llx", value); str(obj, key, text); }
static const char* text(json_t* obj, const char* key) { const char* p = json_string_value(json_object_get(obj, key)); return p ? p : ""; }
static unsigned long long value(json_t* obj, const char* key) {
    auto p = json_object_get(obj, key);
    return json_is_string(p) ? std::strtoull(json_string_value(p), nullptr, 0) : (unsigned long long)json_integer_value(p);
}
static json_t* failure(const char* message) { auto r = json_object(); str(r, "error", message); return r; }
static int append_json(const char* data, size_t size, void* target) { ((std::string*)target)->append(data,size); return 0; }
static bool reg_allowed(const char* reg) {
#ifdef _WIN64
    const char* names[] = {"rax","rbx","rcx","rdx","rsi","rdi","rip","rsp","rbp","r8","r9","r10","r11","r12","r13","r14","r15","eflags"};
#else
    const char* names[] = {"eax","ebx","ecx","edx","esi","edi","eip","esp","ebp","eflags"};
#endif
    for(auto name : names) if(!strcmp(reg,name)) return true;
    return false;
}
// Match the pinned command parser's quoted argument escaping, including trailing
// backslashes. The pipe never accepts an arbitrary command or expression.
static std::string quoted(const char* input) {
    std::string output = "\"";
    for(size_t i = 0; input[i];) {
        if(input[i] != '\\') { if(input[i] == '"' || input[i] == '{') output += '\\'; output += input[i++]; continue; }
        size_t begin = i; while(input[i] == '\\') ++i;
        size_t count = i - begin;
        if(!input[i]) output.append(count * 2, '\\');
        else if(input[i] == '"' || input[i] == '{') { output.append(count * 2 + 1, '\\'); output += input[i++]; }
        else output.append(count, '\\');
    }
    return output + '"';
}

static void callback(CBTYPE type, void* info) {
    if(InterlockedCompareExchange(&ending, 0, 0)) return;
    const char* name = nullptr;
    auto data = json_object();
    switch(type) {
    case CB_INITDEBUG: name = "EVENT_INIT_DEBUG"; str(data, "filename", ((PLUG_CB_INITDEBUG*)info)->szFileName); break;
    case CB_CREATEPROCESS: {
        name = "EVENT_CREATE_PROCESS"; auto p = (PLUG_CB_CREATEPROCESS*)info;
        if(p->fdProcessInfo) { num(data, "dwProcessId", p->fdProcessInfo->dwProcessId); num(data, "dwThreadId", p->fdProcessInfo->dwThreadId); }
        if(p->CreateProcessInfo) address(data, "lpStartAddress", (ULONG_PTR)p->CreateProcessInfo->lpStartAddress);
        str(data, "debugFileName", p->DebugFileName); break;
    }
    case CB_EXITPROCESS: name = "EVENT_EXIT_PROCESS"; num(data, "dwExitCode", ((PLUG_CB_EXITPROCESS*)info)->ExitProcess->dwExitCode); break;
    case CB_STOPDEBUG: name = "EVENT_STOP_DEBUG"; break;
    case CB_SYSTEMBREAKPOINT: name = "EVENT_SYSTEMBREAKPOINT"; break;
    case CB_PAUSEDEBUG: name = "EVENT_PAUSE_DEBUG"; break;
    case CB_RESUMEDEBUG: name = "EVENT_RESUME_DEBUG"; break;
    case CB_STEPPED: name = "EVENT_STEPPED"; break;
    case CB_BREAKPOINT: {
        name = "EVENT_BREAKPOINT"; auto p = ((PLUG_CB_BREAKPOINT*)info)->breakpoint;
        if(p) { address(data, "addr", p->addr); str(data, "name", p->name); num(data, "type", p->type); num(data, "hitCount", p->hitCount); }
        break;
    }
    case CB_EXCEPTION: {
        name = "EVENT_EXCEPTION"; auto p = ((PLUG_CB_EXCEPTION*)info)->Exception;
        if(p) {
            num(data, "ExceptionCode", p->ExceptionRecord.ExceptionCode);
            address(data, "ExceptionAddress", (ULONG_PTR)p->ExceptionRecord.ExceptionAddress);
            num(data, "ExceptionFlags", p->ExceptionRecord.ExceptionFlags);
            flag(data, "dwFirstChance", p->dwFirstChance != 0);
            auto params = json_array();
            for(DWORD i = 0; i < p->ExceptionRecord.NumberParameters && i < EXCEPTION_MAXIMUM_PARAMETERS; ++i) {
                char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)p->ExceptionRecord.ExceptionInformation[i]);
                json_array_append_new(params, json_string(buf));
            }
            json_object_set_new(data, "ExceptionInformation", params);
        } break;
    }
    case CB_LOADDLL: { name = "EVENT_LOAD_DLL"; auto p = (PLUG_CB_LOADDLL*)info; str(data, "modname", p->modname); if(p->LoadDll) address(data, "lpBaseOfDll", (ULONG_PTR)p->LoadDll->lpBaseOfDll); break; }
    case CB_UNLOADDLL: { name = "EVENT_UNLOAD_DLL"; auto p = (PLUG_CB_UNLOADDLL*)info; if(p->UnloadDll) address(data, "lpBaseOfDll", (ULONG_PTR)p->UnloadDll->lpBaseOfDll); break; }
    default: json_decref(data); return;
    }
    auto event = json_object(); str(event, "type", name); json_object_set_new(event, "data", data);
    EnterCriticalSection(&eventLock);
    const auto seq = ++eventSeq; num(event, "seq", seq);
    const auto index = (seq - 1) % 256;
    if(ring[index]) json_decref(ring[index]);
    ring[index] = event;
    LeaveCriticalSection(&eventLock);
}

static json_t* execute(json_t* req) {
    const char* method = text(req, "method");
    auto p = json_object_get(req, "params");
    if(!p) p = req;
    if(!strcmp(method, "hello")) { auto r = json_object(); str(r, "bridge", "ig5-native"); num(r, "protocol", 1); num(r, "pid", GetCurrentProcessId()); num(r, "bits", sizeof(duint) * 8); flag(r,"ownerOnly",true); flag(r,"remoteClientsRejected",true); flag(r,"typedRequests",true); return r; }
    if(!strcmp(method, "state")) {
        auto r = json_object(); flag(r, "debugging", DbgIsDebugging()); flag(r, "running", DbgIsRunning());
        num(r, "pid", DbgIsDebugging() ? DbgGetProcessId() : 0); num(r, "tid", DbgIsDebugging() ? DbgGetThreadId() : 0); return r;
    }
    if(!strcmp(method, "events")) {
        auto result = json_object(), events = json_array(); const auto after = value(p, "after");
        EnterCriticalSection(&eventLock);
        const auto first = eventSeq > 255 ? eventSeq - 255 : 1;
        bool copied = true;
        // Pinned Jansson uses non-atomic reference counts. Never share a ring
        // object with the pipe thread after releasing eventLock.
        for(auto seq = first; seq <= eventSeq; ++seq) if(seq > after) {
            auto copy = json_deep_copy(ring[(seq - 1) % 256]);
            if(!copy) { copied = false; break; }
            json_array_append_new(events,copy);
        }
        num(result, "eventSeq", eventSeq); flag(result, "truncated", after && after + 1 < first);
        LeaveCriticalSection(&eventLock);
        if(!copied) { json_decref(events); json_decref(result); return failure("event snapshot allocation failed"); }
        json_object_set_new(result, "events", events); return result;
    }
    if(!strcmp(method, "cmd")) {
        const char* cmd = text(p, "command");
        const bool allowed = !strcmp(cmd, "run") || !strcmp(cmd, "sti") || !strcmp(cmd, "sto") || !strcmp(cmd, "pause") || !strcmp(cmd, "stop");
        if(!allowed) return failure("command not permitted");
        return json_boolean(DbgCmdExecDirect(cmd));
    }
    if(!strcmp(method,"start")) {
        if(DbgIsDebugging()) return failure("a debuggee is already active");
        const char* path = text(p,"path"), *args = text(p,"args"), *dir = text(p,"dir");
        if(!*path || strlen(path) + strlen(args) + strlen(dir) > 16000) return failure("invalid launch parameters");
        for(auto input : {path,args,dir}) if(strchr(input,'\n') || strchr(input,'\r')) return failure("multiline launch parameter");
        const std::string command = "init " + quoted(path) + ", " + quoted(args) + ", " + quoted(dir);
        return json_boolean(DbgCmdExecDirect(command.c_str()));
    }
    if(!strcmp(method,"trace")) {
        if(!DbgIsDebugging() || DbgIsRunning()) return failure("operation requires a suspended process");
        const auto count = value(p,"count"); if(count < 1 || count > 10000) return failure("invalid trace bound");
        char command[128];
        if(json_object_get(p,"until")) std::snprintf(command,sizeof(command),"ticnd cip==0x%llx, 0x%llx",value(p,"until"),count);
        else std::snprintf(command,sizeof(command),"ticnd 0, 0x%llx",count);
        return json_boolean(DbgCmdExecDirect(command));
    }
    if(!strcmp(method, "eval")) {
        const char* expr = text(p, "expression");
        const bool allowed = reg_allowed(expr) || !strcmp(expr,"cip") || !strcmp(expr,"mod.main()") || !strcmp(expr,"$tracecounter") || std::regex_match(expr,std::regex("mod\\.size\\(0x[0-9a-f]+\\)"));
        if(!allowed || strlen(expr) > 128 || !DbgIsValidExpression(expr)) return failure("invalid expression");
        auto r = json_object(); address(r, "value", DbgValFromString(expr)); return r;
    }
    if(!strcmp(method,"module")) {
        if(!DbgIsDebugging()) return failure("debuggee is not active");
        const duint ea = (duint)value(p,"ea"); auto api = DbgFunctions();
        const duint base = api->ModBaseFromAddr(ea);
        auto result = json_object(); flag(result,"found",base != 0);
        if(base) {
            char name[MAX_MODULE_SIZE] = {}, path[MAX_PATH * 4] = {};
            api->ModNameFromAddr(ea,name,true); api->ModPathFromAddr(ea,path,sizeof(path));
            address(result,"base",base); num(result,"size",api->ModSizeFromAddr(ea));
            str(result,"name",name); str(result,"path",path);
        }
        return result;
    }
    if(!DbgIsDebugging() || DbgIsRunning()) return failure("operation requires a suspended process");
    if(!strcmp(method, "regs")) {
        REGDUMP_AVX512 dump = {};
        if(!DbgGetRegDumpEx(&dump, sizeof(dump))) return failure("register read failed");
        auto r = json_object(); auto& c = dump.regcontext;
#ifdef _WIN64
        address(r,"rax",c.cax); address(r,"rbx",c.cbx); address(r,"rcx",c.ccx); address(r,"rdx",c.cdx);
        address(r,"rsi",c.csi); address(r,"rdi",c.cdi); address(r,"rsp",c.csp); address(r,"rbp",c.cbp); address(r,"rip",c.cip);
        address(r,"r8",c.r8); address(r,"r9",c.r9); address(r,"r10",c.r10); address(r,"r11",c.r11);
        address(r,"r12",c.r12); address(r,"r13",c.r13); address(r,"r14",c.r14); address(r,"r15",c.r15);
#else
        address(r,"eax",c.cax); address(r,"ebx",c.cbx); address(r,"ecx",c.ccx); address(r,"edx",c.cdx);
        address(r,"esi",c.csi); address(r,"edi",c.cdi); address(r,"esp",c.csp); address(r,"ebp",c.cbp); address(r,"eip",c.cip);
#endif
        address(r,"eflags",c.eflags); return r;
    }
    if(!strcmp(method, "setreg")) {
        if(!reg_allowed(text(p,"reg"))) return failure("unsupported register");
        return json_boolean(DbgValSetScalar(text(p, "reg"), (duint)value(p, "value")));
    }
    if(!strcmp(method, "bpt") || !strcmp(method, "unbpt")) {
        char cmd[64]; std::snprintf(cmd, sizeof(cmd), "%s 0x%llx", !strcmp(method, "bpt") ? "bp" : "bc", value(p, "ea"));
        const duint ea = (duint)value(p,"ea");
        const bool ok = DbgCmdExecDirect(cmd);
        const bool exists = (DbgGetBpxTypeAt(ea) & bp_normal) != 0;
        return json_boolean(ok && (exists == !strcmp(method,"bpt")));
    }
    if(!strcmp(method, "memread")) {
        const auto size = value(p, "size"); if(size < 1 || size > 4096) return failure("invalid read size");
        unsigned char buffer[4096];
        if(!DbgMemRead((duint)value(p, "ea"), buffer, (duint)size)) return failure("memory read failed");
        char encoded[8193]; const char* chars = "0123456789abcdef";
        for(size_t i = 0; i < size; ++i) { encoded[2*i] = chars[buffer[i] >> 4]; encoded[2*i+1] = chars[buffer[i] & 15]; }
        encoded[size*2] = 0; return json_string(encoded);
    }
    if(!strcmp(method, "memwrite")) {
        const char* encoded = text(p, "hex"); const auto length = strlen(encoded);
        if(!length || length > 8192 || length % 2) return failure("invalid write size");
        unsigned char buffer[4096];
        for(size_t i = 0; i < length; ++i) if(!isxdigit((unsigned char)encoded[i])) return failure("invalid hex bytes");
        for(size_t i = 0; i < length/2; ++i) { char pair[3] = {encoded[2*i], encoded[2*i+1], 0}; buffer[i] = (unsigned char)strtoul(pair, nullptr, 16); }
        return json_boolean(DbgMemWrite((duint)value(p, "ea"), buffer, (duint)(length/2)));
    }
    if(!strcmp(method, "memmap")) {
        MEMMAP map = {}; if(!DbgMemMap(&map)) return failure("memory map failed");
        auto pages = json_array();
        for(int i = 0; i < map.count; ++i) { auto p = json_object(); auto& page = map.page[i];
            address(p,"base_address",(ULONG_PTR)page.mbi.BaseAddress); address(p,"allocation_base",(ULONG_PTR)page.mbi.AllocationBase);
            num(p,"region_size",page.mbi.RegionSize); num(p,"state",page.mbi.State); num(p,"protect",page.mbi.Protect); num(p,"type",page.mbi.Type); str(p,"info",page.info); json_array_append_new(pages,p);
        }
        BridgeFree(map.page); return pages;
    }
    return failure("unknown bridge method");
}

static DWORD WINAPI serve(void*) {
    const bool connected = ConnectNamedPipe(pipeHandle, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED;
    if(!connected) return 0;
    std::string incoming;
    char buffer[4096]; DWORD got, written;
    while(!InterlockedCompareExchange(&ending,0,0) && ReadFile(pipeHandle, buffer, sizeof(buffer), &got, nullptr) && got) {
        incoming.append(buffer, got);
        if(incoming.size() > 32768) break;
        for(;;) {
            const auto pos = incoming.find('\n'); if(pos == std::string::npos) break;
            const auto line = incoming.substr(0,pos); incoming.erase(0,pos+1);
            json_error_t error = {}; auto request = json_loads(line.c_str(), 0, &error);
            auto result = request ? execute(request) : failure("invalid JSON");
            auto reply = json_object();
            if(request) json_object_set(reply,"id",json_object_get(request,"id"));
            json_object_set_new(reply,"result",result);
            std::string encoded;
            bool ok = json_dump_callback(reply,append_json,&encoded,JSON_COMPACT | JSON_ENCODE_ANY) == 0 && WriteFile(pipeHandle,encoded.data(),(DWORD)encoded.size(),&written,nullptr) && WriteFile(pipeHandle,"\n",1,&written,nullptr);
            json_decref(reply); if(request) json_decref(request);
            if(!ok) return 0;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init) {
    pluginHandle = init->pluginHandle; init->sdkVersion = PLUG_SDKVERSION; init->pluginVersion = 1;
    strcpy_s(init->pluginName, "IG5 Native Bridge");
    InitializeCriticalSection(&eventLock);
    wchar_t name[128]; swprintf_s(name,L"\\\\.\\pipe\\ig5-x64dbg-%lu",GetCurrentProcessId());
    HANDLE token = nullptr; DWORD needed = 0;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) return false;
    GetTokenInformation(token,TokenUser,nullptr,0,&needed);
    std::string tokenBuffer(needed,'\0');
    if(!GetTokenInformation(token,TokenUser,&tokenBuffer[0],needed,&needed)) { CloseHandle(token); return false; }
    CloseHandle(token);
    LPWSTR sid = nullptr;
    if(!ConvertSidToStringSidW(((TOKEN_USER*)tokenBuffer.data())->User.Sid,&sid)) return false;
    const std::wstring sddl = std::wstring(L"D:P(A;;GA;;;") + sid + L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)) return false;
    SECURITY_ATTRIBUTES security = {sizeof(security),descriptor,FALSE};
    pipeHandle = CreateNamedPipeW(name,PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,0,&security);
    LocalFree(descriptor);
    if(pipeHandle == INVALID_HANDLE_VALUE) return false;
    CBTYPE types[] = {CB_INITDEBUG,CB_CREATEPROCESS,CB_EXITPROCESS,CB_STOPDEBUG,CB_SYSTEMBREAKPOINT,CB_PAUSEDEBUG,CB_RESUMEDEBUG,CB_STEPPED,CB_BREAKPOINT,CB_EXCEPTION,CB_LOADDLL,CB_UNLOADDLL};
    for(auto type : types) _plugin_registercallback(pluginHandle,type,callback);
    threadHandle = CreateThread(nullptr,0,serve,nullptr,0,nullptr);
    return threadHandle != nullptr;
}

extern "C" __declspec(dllexport) bool plugstop() {
    InterlockedExchange(&ending,1);
    CancelSynchronousIo(threadHandle); CancelIoEx(pipeHandle,nullptr); DisconnectNamedPipe(pipeHandle);
    if(WaitForSingleObject(threadHandle,2000) != WAIT_OBJECT_0) return false;
    CloseHandle(threadHandle); CloseHandle(pipeHandle);
    // Callback lists are removed by the loader after plugstop. Leave the small
    // ring/critical section alive until DLL teardown to avoid an in-flight race.
    return true;
}
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*) {}

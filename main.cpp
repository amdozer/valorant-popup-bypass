#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsvc.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <io.h>
#include <fcntl.h>
#include <conio.h>
#include <cmath>
#include <ctime>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

void PrintASCIIArt();
void PrintColoredText(const std::wstring& text, bool animated);

class PopupBypass {
private:
    std::vector<DWORD> dnsCacheThreadler;
    std::vector<DWORD> svchostThreadler;
    std::vector<DWORD> askiyaAlinanThreadler;
    HANDLE hDnsCacheProcess;
    DWORD vgcPID;
    DWORD svchostPID;
    bool bypassAktif;
    bool dnsFreezeYapildi;
    
    struct ProcessCpuInfo {
        DWORD pid;
        ULONGLONG lastKernelTime;
        ULONGLONG lastUserTime;
    };
    ProcessCpuInfo vgcCpuInfo;

    bool HataAyiklamaHaklariniEtkinlestir() {
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            CloseHandle(hToken);
            return false;
        }
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        CloseHandle(hToken);
        return true;
    }

    DWORD ProsesBul(const std::wstring& prosesIsmi) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
        
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (!Process32FirstW(hSnapshot, &pe)) {
            CloseHandle(hSnapshot);
            return 0;
        }
        do {
            std::wstring mevcutProses(pe.szExeFile);
            std::transform(mevcutProses.begin(), mevcutProses.end(), mevcutProses.begin(), ::towlower);
            std::wstring hedefProses(prosesIsmi);
            std::transform(hedefProses.begin(), hedefProses.end(), hedefProses.begin(), ::towlower);
            
            if (mevcutProses == hedefProses) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));
        CloseHandle(hSnapshot);
        return 0;
    }

    void ValorantKapat() {
        DWORD valorantPID = ProsesBul(L"VALORANT-Win64-Shipping.exe");
        if (valorantPID != 0) {
            HANDLE hValorant = OpenProcess(PROCESS_TERMINATE, FALSE, valorantPID);
            if (hValorant) {
                TerminateProcess(hValorant, 0);
                CloseHandle(hValorant);
            }
        }
    }

    void KillProcessByName(const wchar_t* processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;
        
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                std::wstring currentProcess(pe.szExeFile);
                std::transform(currentProcess.begin(), currentProcess.end(), currentProcess.begin(), ::towlower);
                std::wstring targetProcess(processName);
                std::transform(targetProcess.begin(), targetProcess.end(), targetProcess.begin(), ::towlower);
                
                if (currentProcess == targetProcess) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProcess) {
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    bool ServisDurdur(const wchar_t* serviceName) {
        SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (!hSCManager) return false;
        
        SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return false;
        }
        
        SERVICE_STATUS_PROCESS ssp;
        DWORD dwBytesNeeded;
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
            if (ssp.dwCurrentState != SERVICE_STOPPED) {
                ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
                for (int i = 0; i < 50; i++) {
                    Sleep(100);
                    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
                        if (ssp.dwCurrentState == SERVICE_STOPPED) break;
                    }
                }
            }
        }
        
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }
    
    bool ServisBaslat(const wchar_t* serviceName) {
        SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (!hSCManager) return false;
        
        SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return false;
        }
        
        SERVICE_STATUS_PROCESS ssp;
        DWORD dwBytesNeeded;
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
            if (ssp.dwCurrentState == SERVICE_STOPPED) {
                StartServiceW(hService, 0, NULL);
                for (int i = 0; i < 50; i++) {
                    Sleep(100);
                    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
                        if (ssp.dwCurrentState == SERVICE_RUNNING) break;
                    }
                }
            }
        }
        
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }
    
    void NetshKomutu(const std::wstring& komut) {
        STARTUPINFOW si = { sizeof(STARTUPINFOW) };
        PROCESS_INFORMATION pi = {};
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        std::wstring cmdLine = L"netsh.exe " + komut;
        std::vector<wchar_t> cmdBuffer(cmdLine.begin(), cmdLine.end());
        cmdBuffer.push_back(L'\0');
        
        CreateProcessW(nullptr, cmdBuffer.data(), nullptr, nullptr, FALSE, 
                      CREATE_NO_WINDOW | CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi);
        
        if (pi.hProcess) {
            WaitForSingleObject(pi.hProcess, 500);  // 500ms'e indirildi
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    void GuvenlikDuvariKuraliEkle(const std::wstring& kuralIsmi, const std::wstring& programYolu, bool giden) {
        std::wstringstream ss;
        ss << L"advfirewall firewall add rule name=\"" << kuralIsmi 
           << L"\" dir=" << (giden ? L"out" : L"in") 
           << L" action=block program=\"" << programYolu 
           << L"\" enable=yes profile=any";
        NetshKomutu(ss.str());
    }

    void GuvenlikDuvariKuraliSil(const std::wstring& kuralIsmi) {
        std::wstringstream ss;
        ss << L"advfirewall firewall delete rule name=\"" << kuralIsmi << L"\"";
        NetshKomutu(ss.str());
    }

    void GuvenlikDuvariEngellemeleri() {
        std::wstring vgcYolu = L"C:\\Program Files\\Riot Vanguard\\vgc.exe";
        std::wstring vgmYolu = L"C:\\Program Files\\Riot Vanguard\\vgm.exe";
        GuvenlikDuvariKuraliEkle(L"Block vgc.exe Outbound", vgcYolu, true);
        GuvenlikDuvariKuraliEkle(L"Block vgm.exe Outbound", vgmYolu, true);
    }

    void GuvenlikDuvariKurallariniTemizle() {
        GuvenlikDuvariKuraliSil(L"Block vgc.exe Outbound");
        GuvenlikDuvariKuraliSil(L"Block vgc.exe Inbound");
        GuvenlikDuvariKuraliSil(L"Block vgm.exe Outbound");
    }

    DWORD GetServicePID(const wchar_t* serviceName) {
        SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCManager) return 0;
        
        SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_QUERY_STATUS);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return 0;
        }
        
        SERVICE_STATUS_PROCESS ssp;
        DWORD dwBytesNeeded;
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return 0;
        }
        
        DWORD pid = ssp.dwProcessId;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return pid;
    }
    
    bool DnsCacheFreeze() {
        ServisDurdur(L"Dnscache");
        Sleep(300);
        ServisBaslat(L"Dnscache");
        Sleep(500);
        
        DWORD dnsPid = GetServicePID(L"Dnscache");
        if (dnsPid == 0) return false;
        
        hDnsCacheProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dnsPid);
        if (!hDnsCacheProcess) return false;
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        dnsCacheThreadler.clear();
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == dnsPid) {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (hThread) {
                        SuspendThread(hThread);
                        dnsCacheThreadler.push_back(te.th32ThreadID);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        CloseHandle(hSnapshot);
        
        dnsFreezeYapildi = !dnsCacheThreadler.empty();
        return dnsFreezeYapildi;
    }
    
    void DnsCacheUnfreeze() {
        for (DWORD threadID : dnsCacheThreadler) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadID);
            if (hThread) {
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }
        dnsCacheThreadler.clear();
        
        if (hDnsCacheProcess) {
            CloseHandle(hDnsCacheProcess);
            hDnsCacheProcess = NULL;
        }
        dnsFreezeYapildi = false;
    }
    
    bool SvchostSuspend() {
        DWORD dnsServicePID = GetServicePID(L"Dnscache");
        if (dnsServicePID == 0) return false;
        
        svchostThreadler.clear();
        bool basarili = false;
        
        HANDLE hSnapshotThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshotThread != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te;
            te.dwSize = sizeof(THREADENTRY32);
            
            if (Thread32First(hSnapshotThread, &te)) {
                do {
                    if (te.th32OwnerProcessID == dnsServicePID) {
                        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                        if (hThread) {
                            SuspendThread(hThread);
                            svchostThreadler.push_back(te.th32ThreadID);
                            basarili = true;
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hSnapshotThread, &te));
            }
            CloseHandle(hSnapshotThread);
        }
        
        if (basarili) {
            svchostPID = dnsServicePID;
        }
        return basarili;
    }
    
    void SvchostResume() {
        for (DWORD threadID : svchostThreadler) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadID);
            if (hThread) {
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }
        svchostThreadler.clear();
        svchostPID = 0;
    }

    double GetVgcCpuUsage() {
        if (vgcPID == 0) return 0.0;
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, vgcPID);
        if (!hProcess) return 0.0;
        
        FILETIME ftCreation, ftExit, ftKernel, ftUser;
        if (!GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
            CloseHandle(hProcess);
            return 0.0;
        }
        
        ULARGE_INTEGER kernel, user;
        kernel.LowPart = ftKernel.dwLowDateTime;
        kernel.HighPart = ftKernel.dwHighDateTime;
        user.LowPart = ftUser.dwLowDateTime;
        user.HighPart = ftUser.dwHighDateTime;
        
        ULONGLONG currentTime = kernel.QuadPart + user.QuadPart;
        double cpuUsage = 0.0;
        
        if (vgcCpuInfo.lastKernelTime != 0) {
            ULONGLONG timeDiff = currentTime - (vgcCpuInfo.lastKernelTime + vgcCpuInfo.lastUserTime);
            if (timeDiff > 0) {
                cpuUsage = (double)timeDiff / 100000.0;
            }
        }
        
        vgcCpuInfo.lastKernelTime = kernel.QuadPart;
        vgcCpuInfo.lastUserTime = user.QuadPart;
        
        CloseHandle(hProcess);
        return cpuUsage;
    }

    void VgcThreadleriniAskiyaAl() {
        if (vgcPID == 0) {
            vgcPID = ProsesBul(L"vgc.exe");
            if (vgcPID == 0) return;
        }
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        std::vector<DWORD> yeniThreadler;
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == vgcPID) {
                    bool zatenVar = false;
                    for (DWORD tid : askiyaAlinanThreadler) {
                        if (tid == te.th32ThreadID) {
                            zatenVar = true;
                            break;
                        }
                    }
                    if (!zatenVar) {
                        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                        if (hThread) {
                            SuspendThread(hThread);
                            yeniThreadler.push_back(te.th32ThreadID);
                            CloseHandle(hThread);
                        }
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        CloseHandle(hSnapshot);
        
        if (!yeniThreadler.empty()) {
            askiyaAlinanThreadler.insert(askiyaAlinanThreadler.end(), yeniThreadler.begin(), yeniThreadler.end());
        }
    }

    void VgcThreadleriniDevamEttir() {
        for (DWORD threadID : askiyaAlinanThreadler) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_INFORMATION, FALSE, threadID);
            if (hThread) {
                SetThreadPriority(hThread, THREAD_PRIORITY_NORMAL);
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }
        askiyaAlinanThreadler.clear();
        
        if (vgcPID != 0) {
            HANDLE hVgc = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, vgcPID);
            if (hVgc) {
                SetPriorityClass(hVgc, NORMAL_PRIORITY_CLASS);
                DWORD_PTR processAffinityMask;
                DWORD_PTR systemAffinityMask;
                if (GetProcessAffinityMask(hVgc, &processAffinityMask, &systemAffinityMask)) {
                    SetProcessAffinityMask(hVgc, systemAffinityMask);
                }
                SIZE_T minWorkingSet = -1;
                SIZE_T maxWorkingSet = -1;
                SetProcessWorkingSetSize(hVgc, minWorkingSet, maxWorkingSet);
                CloseHandle(hVgc);
            }
        }
    }

    static DWORD WINAPI PopupBypassThread(LPVOID lpParam) {
        PopupBypass* self = (PopupBypass*)lpParam;
        self->PopupBypassRutini();
        return 0;
    }

    void PopupBypassRutini() {
        system("cls");
        PrintASCIIArt();
        std::wcout << L"\n";
        std::wcout << L"1. Popup Bypass\n";
        std::wcout << L"2. Safe Exit\n";
        std::wcout << L"3. Cikis\n\n";
        std::wcout << L"Seciminiz: 1\n\n";
        
        PrintColoredText(L"[*] Bypass baslatildi.\n", true);
        PrintColoredText(L"[*] Oyunu aciniz...\n", true);
        
        while (ProsesBul(L"VALORANT-Win64-Shipping.exe") == 0) {
            if (!bypassAktif) return;
            Sleep(500);
        }
        PrintColoredText(L"[+] Oyun tespit edildi!\n", true);
        
        PrintColoredText(L"[*] 8 saniye bekleniyor...\n", true);
        for (int i = 0; i < 80 && bypassAktif; i++) {
            Sleep(100);
        }
        if (!bypassAktif) return;
        
        vgcPID = ProsesBul(L"vgc.exe");
        if (vgcPID == 0) {
            PrintColoredText(L"[*] VGC bekleniyor..\n", true);
            for (int i = 0; i < 10 && vgcPID == 0 && bypassAktif; i++) {
                Sleep(1000);
                vgcPID = ProsesBul(L"vgc.exe");
            }
        }
        if (!bypassAktif || vgcPID == 0) {
            PrintColoredText(L"[-] VGC bulunamadi!\n", true);
            return;
        }
        
        vgcCpuInfo.lastKernelTime = 0;
        vgcCpuInfo.lastUserTime = 0;
        
        PrintColoredText(L"[*] VGC CPU kullanimi izleniyor...\n", true);
        bool cpuSpikeDetected = false;
        while (!cpuSpikeDetected && bypassAktif) {
            double cpu = GetVgcCpuUsage();
            if (cpu >= 0.1) {
                cpuSpikeDetected = true;
                PrintColoredText(L"[+] CPU spike tespit edildi! DNS freeze uygulaniyor...\n", true);
                break;
            }
            Sleep(10);
        }
        if (!bypassAktif) return;
        
        if (!cpuSpikeDetected) {
            PrintColoredText(L"[-] CPU spike tespit edilemedi!\n", true);
            return;
        }
        
        if (DnsCacheFreeze()) {
            PrintColoredText(L"[+] DNS freeze uygulandi!\n", true);
        } else {
            PrintColoredText(L"[-] DNS freeze basarisiz!\n", true);
            return;
        }
        
        PrintColoredText(L"[+] Bypass aktif! (key= F8 sonlandır)\n\n", true);
        std::wcout << L" Devam etmek icin bir tusa basin...\n\n";
    }

    void SafeExitIslemleri() {
        system("cls");
        PrintASCIIArt();
        std::wcout << L"\n";
        std::wcout << L"1. Popup Bypass\n";
        std::wcout << L"2. Safe Exit\n";
        std::wcout << L"3. Cikis\n\n";
        std::wcout << L"Seciminiz: 2\n\n";
        
        PrintColoredText(L"[*] Valorant kapatiliyor...\n", true);
        ValorantKapat();
        Sleep(2000);
        
        PrintColoredText(L"[*] Bypass durduruluyor...\n", true);
        bypassAktif = false;
        Sleep(500);
        
        PrintColoredText(L"[*] DNS unfreeze yapiliyor...\n", true);
        DnsCacheUnfreeze();

        PrintColoredText(L"[*] Firewall kurallari temizleniyor...\n", true);
        GuvenlikDuvariKurallariniTemizle();
        
        ServisDurdur(L"Dnscache");
        Sleep(1000);
        ServisBaslat(L"Dnscache");
        Sleep(1000);
        
        dnsFreezeYapildi = false;
        vgcPID = 0;
        svchostPID = 0;
        dnsCacheThreadler.clear();
        
        PrintColoredText(L"[+] Safe exit tamamlandi!\n\n", true);
        std::wcout << L"[*] Safe exit tamamlandi. \n\n";
    }

    void F8Unfreeze() {
        PrintColoredText(L"\n[*] F8 basildi - Firewall kurallari ekleniyor...\n", true);
        GuvenlikDuvariEngellemeleri();
        PrintColoredText(L"[+] Firewall kurallari eklendi!\n", true);
        PrintColoredText(L"\n[*] Unfreeze yapiliyor...\n", true);
        DnsCacheUnfreeze();
        PrintColoredText(L"[+] Unfreeze tamamlandi!\n", true);
    }

public:
    PopupBypass() : hDnsCacheProcess(NULL), vgcPID(0), svchostPID(0),
                   bypassAktif(false), dnsFreezeYapildi(false) {
        vgcCpuInfo.pid = 0;
        vgcCpuInfo.lastKernelTime = 0;
        vgcCpuInfo.lastUserTime = 0;
    }
    
    ~PopupBypass() {
        bypassAktif = false;
        if (hDnsCacheProcess) {
            CloseHandle(hDnsCacheProcess);
        }
    }

    void BypassBaslat() {
        if (bypassAktif) {
            PrintColoredText(L"[-] Bypass zaten aktif!\n", true);
            return;
        }
        
        HataAyiklamaHaklariniEtkinlestir();
        bypassAktif = true;
        CreateThread(NULL, 0, PopupBypassThread, this, 0, NULL);
        Sleep(100);
    }

    void SafeExit() {
        SafeExitIslemleri();
    }

    void Unfreeze() {
        F8Unfreeze();
    }

    bool IsBypassActive() const {
        return bypassAktif;
    }
};

HANDLE g_hBypass = NULL;
PopupBypass* g_bypass = NULL;

void SetConsoleColor(int r, int g, int b) {
    std::wcout << L"\033[38;2;" << r << L";" << g << L";" << b << L"m";
}

void ResetConsoleColor() {
    std::wcout << L"\033[0m";
}

void PrintColoredText(const std::wstring& text, bool animated = false) {
    if (animated) {
        static int hue = 0;
        hue = (hue + 30) % 360;
        
        double h = hue;
        double s = 1.0;
        double v = 1.0;
        
        double c = v * s;
        double x = c * (1 - abs(fmod(h / 60.0, 2) - 1));
        double m = v - c;
        
        int r, g, b;
        if (h < 60) { r = (int)((c + m) * 255); g = (int)((x + m) * 255); b = (int)(m * 255); }
        else if (h < 120) { r = (int)((x + m) * 255); g = (int)((c + m) * 255); b = (int)(m * 255); }
        else if (h < 180) { r = (int)(m * 255); g = (int)((c + m) * 255); b = (int)((x + m) * 255); }
        else if (h < 240) { r = (int)(m * 255); g = (int)((x + m) * 255); b = (int)((c + m) * 255); }
        else if (h < 300) { r = (int)((x + m) * 255); g = (int)(m * 255); b = (int)((c + m) * 255); }
        else { r = (int)((c + m) * 255); g = (int)(m * 255); b = (int)((x + m) * 255); }
        
        SetConsoleColor(r, g, b);
        std::wcout << text;
        ResetConsoleColor();
    } else {
        std::wcout << text;
    }
}

void PrintASCIIArt() {
    SetConsoleColor(255, 0, 0);
    std::wcout << L"\n";
    std::wcout << L"░█▀▀█ ░█▀▀▀█ ░█▀▀█ ░█─░█ ░█▀▀█    ░█▀▀█ ░█──░█ ░█▀▀█ ─█▀▀█ ░█▀▀▀█ ░█▀▀▀█ \n";
    std::wcout << L"░█▄▄█ ░█──░█ ░█▄▄█ ░█─░█ ░█▄▄█    ░█▀▀▄ ░█▄▄▄█ ░█▄▄█ ░█▄▄█ ─▀▀▀▄▄ ─▀▀▀▄▄ \n";
    std::wcout << L"░█─── ░█▄▄▄█ ░█─── ─▀▄▄▀ ░█───    ░█▄▄█ ──░█── ░█─── ░█─░█ ░█▄▄▄█ ░█▄▄▄█ \n";
    std::wcout << L"\n";
    ResetConsoleColor();
}

DWORD WINAPI HotkeyThread(LPVOID lpParam) {
    bool f8Pressed = false;
    while (true) {
        if (GetAsyncKeyState(VK_F8) & 0x8000) {
            if (!f8Pressed) {
                f8Pressed = true;
                if (g_bypass) {
                    g_bypass->Unfreeze();
                }
            }
        } else {
            f8Pressed = false;
        }
        Sleep(100);
    }
    return 0;
}

DWORD WINAPI WindowSizeMonitor(LPVOID lpParam) {
    HWND hwnd = GetConsoleWindow();
    if (!hwnd) return 0;
    
    RECT targetRect;
    GetWindowRect(hwnd, &targetRect);
    int targetWidth = targetRect.right - targetRect.left;
    int targetHeight = targetRect.bottom - targetRect.top;
    
    while (true) {
        RECT currentRect;
        GetWindowRect(hwnd, &currentRect);
    int currentWidth = currentRect.right - currentRect.left;
    int currentHeight = currentRect.bottom - currentRect.top;
    
    if (currentWidth != targetWidth || currentHeight != targetHeight) {
            MoveWindow(hwnd, currentRect.left, currentRect.top, targetWidth, targetHeight, TRUE);
        }
        
        Sleep(100);
    }
    return 0;
}

int main() {
    HWND hwnd = GetConsoleWindow();
    if (hwnd) {
        LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
        style &= ~WS_THICKFRAME;
        style &= ~WS_MAXIMIZEBOX;
        SetWindowLongPtr(hwnd, GWL_STYLE, style);
        
        RECT rect;
        GetWindowRect(hwnd, &rect);
        int width = 650;
        int height = 450;
        MoveWindow(hwnd, rect.left, rect.top, width, height, TRUE);
        
        HMENU hMenu = GetSystemMenu(hwnd, FALSE);
        if (hMenu) {
            EnableMenuItem(hMenu, SC_SIZE, MF_BYCOMMAND | MF_GRAYED);
            EnableMenuItem(hMenu, SC_MAXIMIZE, MF_BYCOMMAND | MF_GRAYED);
        }
    }
    
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hOut, &csbi);
    
    COORD bufferSize;
    bufferSize.X = 80;
    bufferSize.Y = 25;
    SetConsoleScreenBufferSize(hOut, bufferSize);
    
    SMALL_RECT windowSize;
    windowSize.Left = 0;
    windowSize.Top = 0;
    windowSize.Right = 79;
    windowSize.Bottom = 24;
    SetConsoleWindowInfo(hOut, TRUE, &windowSize);
    
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
    
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);
    
    PopupBypass bypass;
    g_bypass = &bypass;
    
    CreateThread(NULL, 0, HotkeyThread, NULL, 0, NULL);
    
    CreateThread(NULL, 0, WindowSizeMonitor, NULL, 0, NULL);
    
    int secim = 0;
    
    while (true) {
        system("cls");
        PrintASCIIArt();
        std::wcout << L"\n";
        std::wcout << L"1. Popup Bypass\n";
        std::wcout << L"2. Safe Exit\n";
        std::wcout << L"3. Cikis\n\n";
        std::wcout << L"Seciminiz: ";
        
        std::wcin >> secim;
        
        if (secim == 1) {
            bypass.BypassBaslat();
            _getch();
        } else if (secim == 2) {
            bypass.SafeExit();
            std::wcout << L"Devam etmek icin bir tusa basin..." << std::endl;
            _getch();
        } else if (secim == 3) {
            bypass.SafeExit();
            break;
        } else {
            std::wcout << L"\n[-] Gecersiz secim!" << std::endl;
            Sleep(1000);
        }
    }
    
    return 0;
}
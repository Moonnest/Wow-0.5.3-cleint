typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef PCONTEXT LPCONTEXT;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _MEMORYSTATUS * LPMEMORYSTATUS;

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA * LPSTARTUPINFOA;

typedef struct _SYSTEM_INFO * LPSYSTEM_INFO;

typedef struct _SYSTEMTIME * LPSYSTEMTIME;

typedef DWORD (* PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _WIN32_FIND_DATAA * LPWIN32_FIND_DATAA;

typedef struct _SYSTEMTIME SYSTEMTIME;

typedef struct _POINTL _POINTL, *P_POINTL;

struct _POINTL {
    LONG x;
    LONG y;
};

typedef WORD ATOM;

typedef DWORD COLORREF;

typedef struct HACCEL__ HACCEL__, *PHACCEL__;

typedef struct HACCEL__ * HACCEL;

struct HACCEL__ {
    int unused;
};

typedef struct HBITMAP__ HBITMAP__, *PHBITMAP__;

typedef struct HBITMAP__ * HBITMAP;

struct HBITMAP__ {
    int unused;
};

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

typedef struct HBRUSH__ * HBRUSH;

struct HBRUSH__ {
    int unused;
};

typedef struct HICON__ HICON__, *PHICON__;

typedef struct HICON__ * HICON;

typedef HICON HCURSOR;

struct HICON__ {
    int unused;
};

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ * HDC;

struct HDC__ {
    int unused;
};

typedef void * HGDIOBJ;

typedef HANDLE HGLOBAL;

typedef struct HGLRC__ HGLRC__, *PHGLRC__;

typedef struct HGLRC__ * HGLRC;

struct HGLRC__ {
    int unused;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

typedef struct HKEY__ * HKEY;

struct HKEY__ {
    int unused;
};

typedef HANDLE HLOCAL;

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ * HMENU;

struct HMENU__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef struct HPEN__ HPEN__, *PHPEN__;

typedef struct HPEN__ * HPEN;

struct HPEN__ {
    int unused;
};

typedef struct HRGN__ HRGN__, *PHRGN__;

typedef struct HRGN__ * HRGN;

struct HRGN__ {
    int unused;
};

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

typedef struct HRSRC__ * HRSRC;

struct HRSRC__ {
    int unused;
};

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ * HWND;

struct HWND__ {
    int unused;
};

typedef int INT;

typedef LONG_PTR LPARAM;

typedef void * LPCVOID;

typedef DWORD * LPDWORD;

typedef struct _FILETIME * LPFILETIME;

typedef HANDLE * LPHANDLE;

typedef long * LPLONG;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT * LPPOINT;

struct tagPOINT {
    LONG x;
    LONG y;
};

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT * LPRECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef struct tagSIZE tagSIZE, *PtagSIZE;

typedef struct tagSIZE * LPSIZE;

struct tagSIZE {
    LONG cx;
    LONG cy;
};
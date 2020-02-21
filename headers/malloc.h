typedef struct _MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION, *P_MEMORY_BASIC_INFORMATION;

struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

typedef struct _OSVERSIONINFOA _OSVERSIONINFOA, *P_OSVERSIONINFOA;

struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[128];
};

typedef DWORD ACCESS_MASK;

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef DWORD LCID;

typedef CHAR * LPCSTR;

typedef struct _OSVERSIONINFOA * LPOSVERSIONINFOA;

typedef CHAR * PCNZCH;

typedef LONG * PLONG;

typedef struct _MEMORY_BASIC_INFORMATION * PMEMORY_BASIC_INFORMATION;

typedef short SHORT;

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef struct fd_set fd_set, *Pfd_set;

typedef uint u_int;

typedef UINT_PTR SOCKET;

struct fd_set {
    u_int fd_count;
    SOCKET fd_array[64];
};

typedef struct hostent hostent, *Phostent;

struct hostent {
    char * h_name;
    char * * h_aliases;
    short h_addrtype;
    short h_length;
    char * * h_addr_list;
};

typedef struct WSAData WSAData, *PWSAData;

typedef struct WSAData WSADATA;

typedef WSADATA * LPWSADATA;

struct WSAData {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    ushort iMaxSockets;
    ushort iMaxUdpDg;
    char * lpVendorInfo;
};

typedef struct sockaddr sockaddr, *Psockaddr;

typedef USHORT ADDRESS_FAMILY;

struct sockaddr {
    ADDRESS_FAMILY sa_family;
    CHAR sa_data[14];
};

typedef struct timeval timeval, *Ptimeval;

struct timeval {
    long tv_sec;
    long tv_usec;
};

typedef ulong u_long;

typedef ushort u_short;

typedef union _union_859 _union_859, *P_union_859;

typedef struct tagMOUSEINPUT tagMOUSEINPUT, *PtagMOUSEINPUT;

typedef struct tagMOUSEINPUT MOUSEINPUT;

typedef struct tagKEYBDINPUT tagKEYBDINPUT, *PtagKEYBDINPUT;

typedef struct tagKEYBDINPUT KEYBDINPUT;

typedef struct tagHARDWAREINPUT tagHARDWAREINPUT, *PtagHARDWAREINPUT;

typedef struct tagHARDWAREINPUT HARDWAREINPUT;

struct tagHARDWAREINPUT {
    DWORD uMsg;
    WORD wParamL;
    WORD wParamH;
};
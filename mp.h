#pragma once
#pragma warning(disable:4996)
#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <time.h>
#include <utility>
#include <string>

#define BOOTENGINE_PARAMS_VERSION 0xA300
#define OPENSCAN_VERSION 0x2C6D
#define RSIG_BOOTENGINE 0x4036
#define RSIG_SCAN_STREAMBUFFER 0x403D
#define PE_CODE_SECTION_NAME ".text"

using u32 = unsigned long;
using u64 = unsigned long long;

typedef u32(*__rsignal)(u32 Code, void* Params, u32 Size);

enum {
    BOOT_CACHEENABLED = 1 << 0,
    BOOT_NOFILECHANGES = 1 << 3,
    BOOT_ENABLECALLISTO = 1 << 6,
    BOOT_REALTIMESIGS = 1 << 8,
    BOOT_DISABLENOTIFICATION = 1 << 9,
    BOOT_CLOUDBHEAVIORBLOCK = 1 << 10,
    BOOT_ENABLELOGGING = 1 << 12,
    BOOT_ENABLEBETA = 1 << 16,
    BOOT_ENABLEIEV = 1 << 17,
    BOOT_ENABLEMANAGED = 1 << 19,
};

enum {
    BOOT_ATTR_NORMAL = 1 << 0,
    BOOT_ATTR_ISXBAC = 1 << 2,
};

enum {
    ENGINE_UNPACK = 1 << 1,
    ENGINE_HEURISTICS = 1 << 3,
    ENGINE_DISABLETHROTTLING = 1 << 11,
    ENGINE_PARANOID = 1 << 12,
    ENGINE_DISABLEANTISPYWARE = 1 << 15,
    ENGINE_DISABLEANTIVIRUS = 1 << 16,
    ENGINE_DISABLENETWORKDRIVES = 1 << 20,
};

enum {
    SCANREASON_UNKNOWN = 0,
    SCANREASON_ONMOUNT = 1,
    SCANREASON_ONOPEN = 2,
    SCANREASON_ONFIRSTREAD = 3,
    SCANREASON_ONWRITE = 4,
    SCANREASON_ONMODIFIEDHANDLECLOSE = 5,
    SCANREASON_INMEMORY = 8,
    SCANREASON_VALIDATION_PRESCAN = 9,
    SCANREASON_VALIDATION_CONTENTSCAN = 0x0A,
    SCANREASON_ONVOLUMECLEANUP = 0x0B,
    SCANREASON_AMSI = 0x0C,
    SCANREASON_AMSI_UAC = 0x0D,
    SCANREASON_GENERICSTREAM = 0x0E,
    SCANREASON_IOAVSTREAM = 0x0F,
};

enum {
    SCANSOURCE_NOTASOURCE = 0,
    SCANSOURCE_SCHEDULED = 1,
    SCANSOURCE_ONDEMAND = 2,
    SCANSOURCE_RTP = 3,
    SCANSOURCE_IOAV_WEB = 4,
    SCANSOURCE_IOAV_FILE = 5,
    SCANSOURCE_CLEAN = 6,
    SCANSOURCE_UCL = 7,
    SCANSOURCE_RTSIG = 8,
    SCANSOURCE_SPYNETREQUEST = 9,
    SCANSOURCE_INFECTIONRESCAN = 0x0A,
    SCANSOURCE_CACHE = 0x0B,
    SCANSOURCE_UNK_TELEMETRY = 0x0C,
    SCANSOURCE_IEPROTECT = 0x0D,
    SCANSOURCE_ELAM = 0x0E,
    SCANSOURCE_LOCAL_ATTESTATION = 0x0F,
    SCANSOURCE_REMOTE_ATTESTATION = 0x10,
    SCANSOURCE_HEARTBEAT = 0x11,
    SCANSOURCE_MAINTENANCE = 0x12,
    SCANSOURCE_MPUT = 0x13,
    SCANSOURCE_AMSI = 0x14,
    SCANSOURCE_STARTUP = 0x15,
    SCANSOURCE_ADDITIONAL_ACTIONS = 0x16,
    SCANSOURCE_AMSI_UAC = 0x17,
    SCANSOURCE_GENSTREAM = 0x18,
    SCANSOURCE_REPORTLOWFI = 0x19,
    SCANSOURCE_REPORTINTERNALDETECTION = 0x19,
    SCANSOURCE_SENSE = 0x1A,
    SCANSOURCE_XBAC = 0x1B,
};

enum {
    SCAN_FILENAME = 1 << 8,
    SCAN_ENCRYPTED = 1 << 6,
    SCAN_MEMBERNAME = 1 << 7,
    SCAN_FILETYPE = 1 << 9,
    SCAN_TOPLEVEL = 1 << 18,
    SCAN_PACKERSTART = 1 << 19,
    SCAN_PACKEREND = 1 << 12,
    SCAN_ISARCHIVE = 1 << 16,
    SCAN_VIRUSFOUND = 1 << 27,
    SCAN_CORRUPT = 1 << 13,
    SCAN_UNKNOWN = 1 << 15,
};

enum {
    STREAM_ATTRIBUTE_INVALID = 0,
    STREAM_ATTRIBUTE_SKIPBMNOTIFICATION = 1,
    STREAM_ATTRIBUTE_BMDATA = 2,
    STREAM_ATTRIBUTE_FILECOPYPERFHINT = 3,
    STREAM_ATTRIBUTE_FILECOPYSOURCEPATH = 4,
    STREAM_ATTRIBUTE_FILECHANGEPERFHINT = 5,
    STREAM_ATTRIBUTE_FILEOPPROCESSID = 6,
    STREAM_ATTRIBUTE_FILEBACKUPWRITEPERFHINT = 7,
    STREAM_ATTRIBUTE_DONOTCACHESCANRESULT = 8,
    STREAM_ATTRIBUTE_SCANREASON = 9,
    STREAM_ATTRIBUTE_FILEID = 10,
    STREAM_ATTRIBUTE_FILEVOLUMESERIALNUMBER = 11,
    STREAM_ATTRIBUTE_FILEUSN = 12,
    STREAM_ATTRIBUTE_SCRIPTTYPE = 13,
    STREAM_ATTRIBUTE_PRIVATE = 14,
    STREAM_ATTRIBUTE_URL = 15,
    STREAM_ATTRIBUTE_REFERRALURL = 16,
    STREAM_ATTRIBUTE_SCRIPTID = 17,
    STREAM_ATTRIBUTE_HOSTAPPVERSION = 18,
    STREAM_ATTRIBUTE_THREAT_ID = 19,
    STREAM_ATTRIBUTE_THREAT_STATUS = 21,
    STREAM_ATTRIBUTE_LOFI = 22,
    STREAM_ATTRIBUTE_THREAT_RESOURCES = 25,
    STREAM_ATTRIBUTE_LOFI_RESOURCES = 26,
    STREAM_ATTRIBUTE_VOLATILE = 29,
    STREAM_ATTRIBUTE_REFERRERURL = 30,
    STREAM_ATTRIBUTE_REQUESTORMODE = 31,
    STREAM_ATTRIBUTE_CI_EA = 33,
    STREAM_ATTRIBUTE_CURRENT_FILEUSN = 34,
    STREAM_ATTRIBUTE_AVAILABLE_DSS_THREADS = 35,
    STREAM_ATTRIBUTE_IO_STATUS_BLOCK_FOR_NEW_FILE = 36,
    STREAM_ATTRIBUTE_DESIRED_ACCESS = 37,
    STREAM_ATTRIBUTE_FILEOPPROCESSNAME = 38,
    STREAM_ATTRIBUTE_DETAILED_SCAN_NEEDED = 39,
    STREAM_ATTRIBUTE_URL_HAS_GOOD_REPUTATION = 40,
    STREAM_ATTRIBUTE_SITE_HAS_GOOD_REPUTATION = 41,
    STREAM_ATTRIBUTE_URL_ZONE = 42,
    STREAM_ATTRIBUTE_CONTROL_GUID = 43,
    STREAM_ATTRIBUTE_CONTROL_VERSION = 44,
    STREAM_ATTRIBUTE_CONTROL_PATH = 45,
    STREAM_ATTRIBUTE_CONTROL_HTML = 46,
    STREAM_ATTRIBUTE_PAGE_CONTEXT = 47,
    STREAM_ATTRIBUTE_FRAME_URL = 48,
    STREAM_ATTRIBUTE_FRAME_HTML = 49,
    STREAM_ATTRIBUTE_ACTION_IE_BLOCK_PAGE = 50,
    STREAM_ATTRIBUTE_ACTION_IE_BLOCK_CONTROL = 51,
    STREAM_ATTRIBUTE_SHARE_ACCESS = 52,
    STREAM_ATTRIBUTE_OPEN_OPTIONS = 53,
    STREAM_ATTRIBUTE_DEVICE_CHARACTERISTICS = 54,
    STREAM_ATTRIBUTE_FILE_ATTRIBUTES = 55,
    STREAM_ATTRIBUTE_HAS_MOTW_ADS = 56,
    STREAM_ATTRIBUTE_SE_SIGNING_LEVEL = 57,
    STREAM_ATTRIBUTE_SESSION_ID = 58,
    STREAM_ATTRIBUTE_AMSI_APP_ID = 59,
    STREAM_ATTRIBUTE_AMSI_SESSION_ID = 60,
    STREAM_ATTRIBUTE_FILE_OPERATION_PPID = 61,
    STREAM_ATTRIBUTE_SECTOR_NUMBER = 62,
    STREAM_ATTRIBUTE_AMSI_CONTENT_NAME = 63,
    STREAM_ATTRIBUTE_AMSI_UAC_REQUEST_CONTEXT = 64,
    STREAM_ATTRIBUTE_RESOURCE_CONTEXT = 65,
    STREAM_ATTRIBUTE_OPEN_CREATEPROCESS_HINT = 66,
    STREAM_ATTRIBUTE_GENSTREAM_APP_NAME = 67,
    STREAM_ATTRIBUTE_GENSTREAM_SESSION_ID = 68,
    STREAM_ATTRIBUTE_GENSTREAM_CONTENT_NAME = 69,
    STREAM_ATTRIBUTE_OPEN_ACCESS_STATE_FLAGS = 70,
    STREAM_ATTRIBUTE_GENSTREAM_EXTERN_GUID = 71,
    STREAM_ATTRIBUTE_IS_CONTAINER_FILE = 72,
    STREAM_ATTRIBUTE_AMSI_REDIRECT_CHAIN = 75,
};

#pragma pack(push, 1)
typedef struct _ENGINE_INFO {
    u32   field_0;
    u32   field_4;
    u32   field_8;
    u32   field_C;
} ENGINE_INFO, * PENGINE_INFO;

typedef struct _ENGINE_CONFIG {
    u64 engine_flags;
    wchar_t* inclusions;
    void* exceptions;
    wchar_t* unk0;
    wchar_t* quarantine_location;
    u32 field_14;
    u32 field_18;
    u32 field_1C;
    u32 field_20;
    u32 field_24;
    u32 field_28;
    u64 field_2C;
    u64 field_30;
    u64 field_34;
    PCHAR unk1;
    PCHAR unk2;
} ENGINE_CONFIG, * PENGINE_CONFIG;

typedef struct _ENGINE_CONTEXT {
    u32   field_0;
} ENGINE_CONTEXT, * PENGINE_CONTEXT;

typedef struct _BOOTENGINE_PARAMS {
    u64           client_version;
    wchar_t* sigs_location;
    void* spynet_src;
    PENGINE_CONFIG  engine_cfg;
    PENGINE_INFO    engine_info;
    wchar_t* scan_report_location;
    u32           boot_flags;
    wchar_t* local_copy_dir;
    wchar_t* offline_target_os;
    CHAR            product_id[16];
    u64           field_34;
    void* global_callback;
    PENGINE_CONTEXT engine_ctx;
    u64           avg_cpu_load;
    CHAR            field_44[16];
    wchar_t* spynet_report_guid;
    wchar_t* spynet_version;
    wchar_t* nis_engine_version;
    wchar_t* nis_sigs_version;
    u64           flighting_enabled;
    u32           flighting_level;
    void* dynamic_cfg;
    u32           auto_sample_submission;
    u32           enable_thread_logging;
    wchar_t* product_name;
    u32           passive_mode;
    u32           sense_enabled;
    wchar_t* sense_org_id;
    u32           attrs;
    u32           block_at_first_seen;
    u32           pua_protection;
    u32           side_by_side_passive_mode;
    u64 a;
    u64 b;
    u64 c;
    u64 d;
    u64 e;
    u64 f;
    u64 g;
    u64 h;
    u64 i;
    u64 j;
    u64 k;
    u64 l;
    u64 m;
    u64 n;
    u64 o;
    u64 p;
    u64 q;
    u64 r;
    u64 s;
    u64 t;
    u64 u;
    u64 v;
    u64 w;
    u64 x;
    u64 y;
    u64 z;
} BOOTENGINE_PARAMS, * PBOOTENGINE_PARAMS;

typedef struct _SCANSTRUCT {
    u32 status;
    u32 flags;
    PCHAR file_name;
    CHAR  identifier[28];
    u32 field_2C;
    u32 field_30;
    u32 field_34;
    u32 field_38;
    u32 field_3C;
    u32 field_40;
    u32 field_44;
    u32 field_48;
    u32 field_4C;
    u64 file_size;
    u64 tag;
    u32 field_60;
    u32 field_64;
    PCHAR file_name_2;
    wchar_t* stream_name;
    wchar_t* _stream_name;
    u32 field_6C;
    u32 thread_id; // GetThreatInfo
} SCANSTRUCT, * PSCANSTRUCT;

typedef struct _SCAN_REPLY {
    u64(*engine_scan_callback)(PSCANSTRUCT _this);
    u64     field_4;
    u64   tag;
    u64     flags;
} SCAN_REPLY, * PSCAN_REPLY;

typedef struct _STREAMBUFFER_DESCRIPTOR {
    FILE* tag;
    u64(*read)(void*, u32, void*, u32, u32*);
    u64(*write)(void*, u64, void*, u32, u32*);
    u64(*get_size)(void*, u64*);
    u64(*set_size)(void*, u64*);
    wchar_t* (*get_name)(void*);
    u64(*set_attributes)(void*, u32, void*, u32);
    u64(*get_attributes)(void*, u32, void*, u32, u32*);
} STREAMBUFFER_DESCRIPTOR, * PSTREAMBUFFER_DESCRIPTOR;

typedef struct _SCANSTREAM_PARAMS {
    PSTREAMBUFFER_DESCRIPTOR      descriptor;
    PSCAN_REPLY                   scan_reply;
    u64                       unk0;
    u64                       unk1;
} SCANSTREAM_PARAMS, * PSCANSTREAM_PARAMS;
#pragma pack(pop)

namespace defender
{
    std::string base_folder = "";

    struct scan_t
    {
        PSCANSTRUCT result;
        int type; // 0 = buffer, 1 = file
        char* data;
        size_t size; // file or buffer
        wchar_t* stream_name;
    };

    static int enable_logging = 0;
    HMODULE mpengine_base;
    __rsignal prsignal;
    thread_local scan_t* cur_scan = nullptr;

    static void log(const char* format, ...)
    {
        if (!enable_logging) {
            return;
        }

        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }

    static u64 scan_callback(PSCANSTRUCT result)
    {
        if (result->flags & SCAN_MEMBERNAME) {
            log("[+] scanning archive member %s ...\n", result->identifier);
        }

        if (result->flags & SCAN_FILENAME) {
            log("[+] scanning %s ...\n", result->file_name);
        }

        if (result->flags & SCAN_PACKERSTART) {
            log("[+] packer %s identified.\n", result->identifier);
        }

        if (result->flags & SCAN_ENCRYPTED) {
            log("[+] file may be encrypted.\n");
        }

        if (result->flags & SCAN_CORRUPT) {
            log("[+] file may be corrupt.\n");
        }

        if (result->flags & SCAN_FILETYPE) {
            log("[+] file %s is identified as %s\n", result->file_name, result->identifier);
        }

        if (result->flags & 0x08000022) {
            log("[+] threat %s identified.\n", result->identifier);
        }

        if ((result->flags & 0x40010000) == 0x40010000) {
            log("[+] threat %s identified (PUA).\n", result->identifier);
        }

        cur_scan->result = result;
        return 0;
    }

    static size_t read_stream(void* _this, u32 offset, void* buffer, u32 size, u32* nsize)
    {
        if (offset >= cur_scan->size) {
            *nsize = 0;
            return TRUE;
        }
        size_t remaining = cur_scan->size - offset;
        size_t to_read = (size < remaining) ? size : remaining;
        memcpy(buffer, (BYTE*)cur_scan->data + offset, to_read);
        *nsize = to_read;
        return TRUE;
    }

    static u64 get_stream_size(void* _this, u64* size)
    {
        *size = cur_scan->size;
        return 0;
    }

    static wchar_t* get_stream_name(void* self)
    {
        return cur_scan->stream_name ? cur_scan->stream_name : (wchar_t*)L"unnamed buffer";
    }

    static u64 get_attributes(void* _this, u32 attributeId, void* buffer, u32 x, u32* size)
    {
        return 0;
    }

    wchar_t* c2wc(char* c)
    {
        size_t cSize = strlen(c) + 1;
        wchar_t* wc = new wchar_t[cSize];
        mbstowcs(wc, c, cSize);
        return wc;
    }

    int scan(scan_t* _scan)
    {
        cur_scan = _scan;

        SCANSTREAM_PARAMS scan_params;
        STREAMBUFFER_DESCRIPTOR scan_desc;
        SCAN_REPLY scan_reply;

        memset(&scan_params, 0, sizeof scan_params);
        scan_params.descriptor = &scan_desc;
        scan_params.scan_reply = &scan_reply;

        memset(&scan_reply, 0, sizeof scan_reply);
        scan_reply.engine_scan_callback = scan_callback;
        scan_reply.flags = 0x7fffffff;

        memset(&scan_desc, 0, sizeof scan_desc);
        scan_desc.read = read_stream;
        scan_desc.get_size = get_stream_size;
        scan_desc.get_name = get_stream_name;
        scan_desc.get_attributes = get_attributes;
        scan_desc.tag = (FILE*)1337;

        int r = prsignal(RSIG_SCAN_STREAMBUFFER, &scan_params, sizeof(scan_params));
        return r;
    }

    int boot(std::string _base_folder, std::string _inclusions)
    {
        base_folder = _base_folder;

        mpengine_base = LoadLibraryA((base_folder + "\\mpengine.dll").c_str());
        prsignal = (__rsignal)GetProcAddress(mpengine_base, "rsignal");
        if (!mpengine_base || !prsignal) {
            log("[!] failed to load mpengine. module missing?\n");
            return -1;
        }

        BOOTENGINE_PARAMS boot_params;
        ENGINE_INFO engine_info;
        ENGINE_CONFIG engine_cfg;

        log("[+] booting engine...\n");

        memset(&boot_params, 0, sizeof boot_params);
        memset(&engine_info, 0, sizeof engine_info);
        memset(&engine_cfg, 0, sizeof engine_cfg);

        boot_params.client_version = BOOTENGINE_PARAMS_VERSION;
        boot_params.sigs_location = c2wc((char*)base_folder.c_str());;
        boot_params.attrs = BOOT_ATTR_NORMAL;
        boot_params.product_name = (wchar_t*)L"mp.h";
        engine_cfg.quarantine_location = (wchar_t*)L"quarantine";
        engine_cfg.inclusions = c2wc((char*)_inclusions.c_str());
        engine_cfg.engine_flags = 1 << 1;
        engine_cfg.unk1 = NULL;
        engine_cfg.unk2 = NULL;
        boot_params.engine_info = &engine_info;
        boot_params.engine_cfg = &engine_cfg;

        SetCurrentDirectoryA(base_folder.c_str());
        int status = prsignal(RSIG_BOOTENGINE, &boot_params, sizeof boot_params); //
        log("[*] engine status: %d\n", status);

        return status;
    }

    std::pair<int, PSCANSTRUCT> scan_buffer(char* buffer, size_t size, wchar_t* stream_name = 0)
    {
        scan_t _scan = { 0 };
        _scan.data = buffer;
        _scan.type = 0;
        _scan.size = size;
        _scan.result = 0;
		_scan.stream_name = stream_name;

        int status = scan(&_scan);
        return { status, _scan.result };
    }

    std::pair<int, PSCANSTRUCT> scan_file(const char* file_path)
    {
        FILE* fp = fopen(file_path, "rb");
        if (!fp) {
            log("[!] Failed to open file: %s\n", file_path);
            return { -1, 0 };
        }

        fseek(fp, 0, SEEK_END);
        size_t file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        char* file_data = (char*)malloc(file_size);
        size_t bytes_read = fread(file_data, 1, file_size, fp);
        fclose(fp);

        scan_t _scan = { 0 };
        _scan.data = file_data;
        _scan.type = 1;
        _scan.size = file_size;
        _scan.result = 0;
        _scan.stream_name = c2wc((char*)file_path);

        int status = scan(&_scan);
        free(file_data);
        return { status, _scan.result };
    }
}

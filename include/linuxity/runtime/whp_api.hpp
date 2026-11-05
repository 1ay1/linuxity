// linuxity/runtime/whp_api.hpp
//
// The Windows Hypervisor Platform entry points, resolved at RUNTIME.
//
// Why not just link WinHvPlatform.lib? Because WHP is an optional Windows
// feature ("Windows Hypervisor Platform" in Add Features, which itself needs
// virtualization enabled in firmware). If we link the import library, the
// loader resolves WinHvPlatform.dll at PROCESS START, and on a machine where
// the feature is off the binary dies with 0xC0000135 before `main` runs --
// the user sees a Windows error box, not a diagnostic. That is unacceptable
// for a tool whose Linux and macOS builds run fine: `linuxity --version` and
// the portable core must work everywhere.
//
// So we LoadLibrary on demand and report a real error. This also keeps the
// build independent of whether the SDK that compiled it shipped the WHP
// import library, and lets the whole backend compile on any Windows SDK --
// including MinGW, whose headers historically lag on WinHvPlatform.h.
//
// To that end the types below are declared locally rather than included from
// WinHvPlatform.h, guarded so that a real SDK header wins if it is present.
// The ABI is stable and documented; the values are from the public headers.
#pragma once

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <windows.h>

#include <cstdint>
#include <type_traits>

// If the SDK provides the real header, prefer it -- our declarations are a
// fallback for toolchains that lack it, not a replacement.
#if defined(__has_include)
#  if __has_include(<WinHvPlatform.h>)
#    include <WinHvPlatform.h>
#    define LX_WHP_SDK_HEADER 1
#  endif
#endif

#ifndef LX_WHP_SDK_HEADER

// ---------------------------------------------------------------------------
// Minimal WHP ABI declarations (mirroring WinHvPlatformDefs.h).
// ---------------------------------------------------------------------------
extern "C" {

typedef VOID* WHV_PARTITION_HANDLE;

typedef enum WHV_CAPABILITY_CODE {
    WHvCapabilityCodeHypervisorPresent  = 0x00000000,
    WHvCapabilityCodeFeatures           = 0x00000001,
    WHvCapabilityCodeExtendedVmExits    = 0x00000002,
    WHvCapabilityCodeExceptionExitBitmap = 0x00000003,
} WHV_CAPABILITY_CODE;

typedef enum WHV_PARTITION_PROPERTY_CODE {
    WHvPartitionPropertyCodeExtendedVmExits      = 0x00000001,
    WHvPartitionPropertyCodeExceptionExitBitmap  = 0x00000002,
    WHvPartitionPropertyCodeProcessorCount       = 0x00001fff,
} WHV_PARTITION_PROPERTY_CODE;

// Bit positions within ExtendedVmExits.
typedef union WHV_EXTENDED_VM_EXITS {
    UINT64 AsUINT64;
    struct {
        UINT64 X64CpuidExit      : 1;
        UINT64 X64MsrExit        : 1;
        UINT64 ExceptionExit     : 1;
        UINT64 Reserved          : 61;
    };
} WHV_EXTENDED_VM_EXITS;

// x86 exception vectors, as used in ExceptionExitBitmap (bit N = vector N).
typedef enum WHV_EXCEPTION_TYPE {
    WHvX64ExceptionTypeDebugTrapOrFault     = 0x01,
    WHvX64ExceptionTypeBreakpointTrap       = 0x03,
    WHvX64ExceptionTypeInvalidOpcodeFault   = 0x06,
    WHvX64ExceptionTypeGeneralProtectionFault = 0x0D,
    WHvX64ExceptionTypePageFault            = 0x0E,
} WHV_EXCEPTION_TYPE;

typedef union WHV_PARTITION_PROPERTY {
    UINT64 AsUINT64;
    UINT32 ProcessorCount;
    WHV_EXTENDED_VM_EXITS ExtendedVmExits;
    UINT64 ExceptionExitBitmap;
} WHV_PARTITION_PROPERTY;

typedef union WHV_CAPABILITY {
    UINT64 AsUINT64;
    BOOL HypervisorPresent;
    UINT64 ExceptionExitBitmap;
    WHV_EXTENDED_VM_EXITS ExtendedVmExits;
} WHV_CAPABILITY;

typedef enum WHV_MAP_GPA_RANGE_FLAGS {
    WHvMapGpaRangeFlagNone     = 0x00000000,
    WHvMapGpaRangeFlagRead     = 0x00000001,
    WHvMapGpaRangeFlagWrite    = 0x00000002,
    WHvMapGpaRangeFlagExecute  = 0x00000004,
} WHV_MAP_GPA_RANGE_FLAGS;

typedef enum WHV_RUN_VP_EXIT_REASON {
    WHvRunVpExitReasonNone                   = 0x00000000,
    WHvRunVpExitReasonMemoryAccess           = 0x00000001,
    WHvRunVpExitReasonX64IoPortAccess        = 0x00000002,
    WHvRunVpExitReasonUnrecoverableException = 0x00000004,
    WHvRunVpExitReasonInvalidVpRegisterValue = 0x00000005,
    WHvRunVpExitReasonUnsupportedFeature     = 0x00000006,
    WHvRunVpExitReasonX64InterruptWindow     = 0x00000007,
    WHvRunVpExitReasonX64Halt                = 0x00000008,
    WHvRunVpExitReasonX64ApicEoi             = 0x00000009,
    WHvRunVpExitReasonX64MsrAccess           = 0x00001000,
    WHvRunVpExitReasonX64Cpuid               = 0x00001001,
    WHvRunVpExitReasonException              = 0x00001002,
    WHvRunVpExitReasonX64Rdtsc               = 0x00001003,
    WHvRunVpExitReasonCanceled               = 0x00002001,
} WHV_RUN_VP_EXIT_REASON;

// Register names (subset: the GPRs, RIP/RFLAGS, segments, control regs, MSRs).
typedef enum WHV_REGISTER_NAME {
    WHvX64RegisterRax = 0x00000000,
    WHvX64RegisterRcx = 0x00000001,
    WHvX64RegisterRdx = 0x00000002,
    WHvX64RegisterRbx = 0x00000003,
    WHvX64RegisterRsp = 0x00000004,
    WHvX64RegisterRbp = 0x00000005,
    WHvX64RegisterRsi = 0x00000006,
    WHvX64RegisterRdi = 0x00000007,
    WHvX64RegisterR8  = 0x00000008,
    WHvX64RegisterR9  = 0x00000009,
    WHvX64RegisterR10 = 0x0000000A,
    WHvX64RegisterR11 = 0x0000000B,
    WHvX64RegisterR12 = 0x0000000C,
    WHvX64RegisterR13 = 0x0000000D,
    WHvX64RegisterR14 = 0x0000000E,
    WHvX64RegisterR15 = 0x0000000F,
    WHvX64RegisterRip = 0x00000010,
    WHvX64RegisterRflags = 0x00000011,

    WHvX64RegisterEs  = 0x00000012,
    WHvX64RegisterCs  = 0x00000013,
    WHvX64RegisterSs  = 0x00000014,
    WHvX64RegisterDs  = 0x00000015,
    WHvX64RegisterFs  = 0x00000016,
    WHvX64RegisterGs  = 0x00000017,
    WHvX64RegisterLdtr = 0x00000018,
    WHvX64RegisterTr  = 0x00000019,
    WHvX64RegisterIdtr = 0x0000001A,
    WHvX64RegisterGdtr = 0x0000001B,

    WHvX64RegisterCr0 = 0x0000001C,
    WHvX64RegisterCr2 = 0x0000001D,
    WHvX64RegisterCr3 = 0x0000001E,
    WHvX64RegisterCr4 = 0x0000001F,
    WHvX64RegisterCr8 = 0x00000020,

    WHvX64RegisterEfer    = 0x00002001,
    WHvX64RegisterKernelGsBase = 0x00002002,
    WHvX64RegisterStar    = 0x00002005,
    WHvX64RegisterLstar   = 0x00002006,
    WHvX64RegisterCstar   = 0x00002007,
    WHvX64RegisterSfmask  = 0x00002008,
    WHvX64RegisterFsBase  = 0x00002013,
    WHvX64RegisterGsBase  = 0x00002014,
} WHV_REGISTER_NAME;

typedef struct WHV_X64_SEGMENT_REGISTER {
    UINT64 Base;
    UINT32 Limit;
    UINT16 Selector;
    union {
        UINT16 Attributes;
        struct {
            UINT16 SegmentType    : 4;
            UINT16 NonSystemSegment : 1;
            UINT16 DescriptorPrivilegeLevel : 2;
            UINT16 Present        : 1;
            UINT16 Reserved       : 4;
            UINT16 Available      : 1;
            UINT16 Long           : 1;
            UINT16 Default        : 1;
            UINT16 Granularity    : 1;
        };
    };
} WHV_X64_SEGMENT_REGISTER;

typedef struct WHV_X64_TABLE_REGISTER {
    UINT16 Pad[3];
    UINT16 Limit;
    UINT64 Base;
} WHV_X64_TABLE_REGISTER;

typedef union DECLSPEC_ALIGN(16) WHV_REGISTER_VALUE {
    UINT64 Reg64;
    UINT32 Reg32;
    UINT16 Reg16;
    UINT8  Reg8;
    WHV_X64_SEGMENT_REGISTER Segment;
    WHV_X64_TABLE_REGISTER   Table;
    UINT8 Raw[16];
} WHV_REGISTER_VALUE;

typedef union WHV_X64_VP_EXECUTION_STATE {
    UINT16 AsUINT16;
    struct {
        UINT16 Cpl            : 2;
        UINT16 Cr0Pe          : 1;
        UINT16 Cr0Am          : 1;
        UINT16 EferLma        : 1;
        UINT16 DebugActive    : 1;
        UINT16 InterruptionPending : 1;
        UINT16 Reserved0      : 5;
        UINT16 InterruptShadow : 1;
        UINT16 Reserved1      : 3;
    };
} WHV_X64_VP_EXECUTION_STATE;

typedef struct WHV_VP_EXIT_CONTEXT {
    WHV_X64_VP_EXECUTION_STATE ExecutionState;
    UINT8  InstructionLength : 4;
    UINT8  Cr8 : 4;
    UINT8  Reserved;
    UINT32 Reserved2;
    WHV_X64_SEGMENT_REGISTER Cs;
    UINT64 Rip;
    UINT64 Rflags;
} WHV_VP_EXIT_CONTEXT;

typedef union WHV_MEMORY_ACCESS_INFO {
    UINT32 AsUINT32;
    struct {
        UINT32 AccessType : 2;   // 0=read 1=write 2=execute
        UINT32 GpaUnmapped : 1;
        UINT32 GvaValid : 1;
        UINT32 Reserved : 28;
    };
} WHV_MEMORY_ACCESS_INFO;

typedef struct WHV_MEMORY_ACCESS_CONTEXT {
    UINT8 InstructionByteCount;
    UINT8 Reserved[3];
    UINT8 InstructionBytes[16];
    WHV_MEMORY_ACCESS_INFO AccessInfo;
    UINT64 Gpa;
    UINT64 Gva;
} WHV_MEMORY_ACCESS_CONTEXT;

typedef union WHV_VP_EXCEPTION_INFO {
    UINT32 AsUINT32;
    struct {
        UINT32 ErrorCodeValid : 1;
        UINT32 SoftwareException : 1;
        UINT32 Reserved : 30;
    };
} WHV_VP_EXCEPTION_INFO;

typedef struct WHV_VP_EXCEPTION_CONTEXT {
    UINT8 InstructionByteCount;
    UINT8 Reserved[3];
    UINT8 InstructionBytes[16];
    WHV_VP_EXCEPTION_INFO ExceptionInfo;
    UINT8 ExceptionType;         // the vector: 6 for #UD
    UINT8 Reserved2[3];
    UINT32 ErrorCode;
    UINT64 ExceptionParameter;
} WHV_VP_EXCEPTION_CONTEXT;

typedef struct WHV_RUN_VP_CANCELED_CONTEXT {
    UINT32 CancelReason;
} WHV_RUN_VP_CANCELED_CONTEXT;

typedef struct WHV_RUN_VP_EXIT_CONTEXT {
    WHV_RUN_VP_EXIT_REASON ExitReason;
    UINT32 Reserved;
    WHV_VP_EXIT_CONTEXT VpContext;
    union {
        WHV_MEMORY_ACCESS_CONTEXT MemoryAccess;
        WHV_VP_EXCEPTION_CONTEXT  VpException;
        WHV_RUN_VP_CANCELED_CONTEXT CancelReason;
        UINT8 Reserved2[272];
    };
} WHV_RUN_VP_EXIT_CONTEXT;

} // extern "C"

#endif // !LX_WHP_SDK_HEADER

namespace lx::runtime {

// -- The resolved entry points --------------------------------------------
// One lazily-initialized table. Every call site goes through `whp()`, so
// "is WHP available" is answered in exactly one place.
struct WhpApi {
    HRESULT (WINAPI* GetCapability)(WHV_CAPABILITY_CODE, VOID*, UINT32, UINT32*) = nullptr;
    HRESULT (WINAPI* CreatePartition)(WHV_PARTITION_HANDLE*) = nullptr;
    HRESULT (WINAPI* SetupPartition)(WHV_PARTITION_HANDLE) = nullptr;
    HRESULT (WINAPI* DeletePartition)(WHV_PARTITION_HANDLE) = nullptr;
    HRESULT (WINAPI* SetPartitionProperty)(WHV_PARTITION_HANDLE,
                WHV_PARTITION_PROPERTY_CODE, const VOID*, UINT32) = nullptr;
    HRESULT (WINAPI* MapGpaRange)(WHV_PARTITION_HANDLE, VOID*, UINT64, UINT64,
                WHV_MAP_GPA_RANGE_FLAGS) = nullptr;
    HRESULT (WINAPI* UnmapGpaRange)(WHV_PARTITION_HANDLE, UINT64, UINT64) = nullptr;
    HRESULT (WINAPI* CreateVirtualProcessor)(WHV_PARTITION_HANDLE, UINT32, UINT32) = nullptr;
    HRESULT (WINAPI* DeleteVirtualProcessor)(WHV_PARTITION_HANDLE, UINT32) = nullptr;
    HRESULT (WINAPI* RunVirtualProcessor)(WHV_PARTITION_HANDLE, UINT32, VOID*, UINT32) = nullptr;
    HRESULT (WINAPI* CancelRunVirtualProcessor)(WHV_PARTITION_HANDLE, UINT32, UINT32) = nullptr;
    HRESULT (WINAPI* GetVirtualProcessorRegisters)(WHV_PARTITION_HANDLE, UINT32,
                const WHV_REGISTER_NAME*, UINT32, WHV_REGISTER_VALUE*) = nullptr;
    HRESULT (WINAPI* SetVirtualProcessorRegisters)(WHV_PARTITION_HANDLE, UINT32,
                const WHV_REGISTER_NAME*, UINT32, const WHV_REGISTER_VALUE*) = nullptr;

    // Non-null once every symbol above resolved.
    bool loaded = false;
    // Why loading failed, for a diagnostic the user can act on.
    const char* why = "not initialized";

    [[nodiscard]] bool ok() const noexcept { return loaded; }
};

inline const WhpApi& whp() noexcept {
    static const WhpApi api = [] {
        WhpApi a{};
        HMODULE m = ::LoadLibraryW(L"WinHvPlatform.dll");
        if (!m) {
            a.why = "WinHvPlatform.dll not found -- enable the "
                    "\"Windows Hypervisor Platform\" optional feature "
                    "(and virtualization in firmware)";
            return a;
        }
        auto sym = [&](auto& fp, const char* name) {
            fp = reinterpret_cast<std::remove_reference_t<decltype(fp)>>(
                reinterpret_cast<void*>(::GetProcAddress(m, name)));
            return fp != nullptr;
        };
        const bool all =
            sym(a.GetCapability, "WHvGetCapability") &&
            sym(a.CreatePartition, "WHvCreatePartition") &&
            sym(a.SetupPartition, "WHvSetupPartition") &&
            sym(a.DeletePartition, "WHvDeletePartition") &&
            sym(a.SetPartitionProperty, "WHvSetPartitionProperty") &&
            sym(a.MapGpaRange, "WHvMapGpaRange") &&
            sym(a.UnmapGpaRange, "WHvUnmapGpaRange") &&
            sym(a.CreateVirtualProcessor, "WHvCreateVirtualProcessor") &&
            sym(a.DeleteVirtualProcessor, "WHvDeleteVirtualProcessor") &&
            sym(a.RunVirtualProcessor, "WHvRunVirtualProcessor") &&
            sym(a.CancelRunVirtualProcessor, "WHvCancelRunVirtualProcessor") &&
            sym(a.GetVirtualProcessorRegisters, "WHvGetVirtualProcessorRegisters") &&
            sym(a.SetVirtualProcessorRegisters, "WHvSetVirtualProcessorRegisters");
        if (!all) {
            a.why = "WinHvPlatform.dll is present but missing expected exports";
            return a;
        }
        a.loaded = true;
        a.why = "ok";
        return a;
    }();
    return api;
}

// Is a hypervisor actually running underneath us? The DLL can load on a
// machine where Hyper-V is installed but not enabled, and in that case every
// partition call fails -- so ask before building anything.
[[nodiscard]] inline bool hypervisor_present() noexcept {
    if (!whp().ok()) return false;
    WHV_CAPABILITY cap{};
    UINT32 written = 0;
    if (FAILED(whp().GetCapability(WHvCapabilityCodeHypervisorPresent, &cap,
                                   sizeof(cap), &written)))
        return false;
    return written >= sizeof(BOOL) && cap.HypervisorPresent != FALSE;
}

// Can the partition deliver an exception as a VM exit? Without this the whole
// #UD-on-syscall trap mechanism is impossible, so the backend checks it up
// front rather than failing mysteriously on the first guest syscall.
[[nodiscard]] inline bool exception_exit_supported() noexcept {
    if (!whp().ok()) return false;
    WHV_CAPABILITY cap{};
    UINT32 written = 0;
    if (FAILED(whp().GetCapability(WHvCapabilityCodeExtendedVmExits, &cap,
                                   sizeof(cap), &written)))
        return false;
    return written >= sizeof(UINT64) && cap.ExtendedVmExits.ExceptionExit != 0;
}

// Cryptographic random bytes, for AT_RANDOM (the guest's stack-protector and
// pointer-guard seed). RtlGenRandom (exposed as SystemFunction036) is the
// CSPRNG the Windows CRT uses underneath and needs no CryptoAPI handle; a
// fixed or rand()-derived value here would make every guest's canary
// identical, silently destroying the mitigation the guest believes it has.
[[nodiscard]] inline bool whp_random_bytes(void* buf, unsigned len) noexcept {
    using RtlGenRandomFn = BOOLEAN(WINAPI*)(PVOID, ULONG);
    static const RtlGenRandomFn gen = [] {
        HMODULE m = ::LoadLibraryW(L"advapi32.dll");
        return m ? reinterpret_cast<RtlGenRandomFn>(reinterpret_cast<void*>(
                       ::GetProcAddress(m, "SystemFunction036")))
                 : nullptr;
    }();
    return gen && gen(buf, len) != FALSE;
}

[[nodiscard]] inline const char* whp_unavailable_reason() noexcept {
    if (!whp().ok()) return whp().why;
    if (!hypervisor_present())
        return "no hypervisor running -- enable Hyper-V / Windows Hypervisor "
               "Platform and virtualization in firmware";
    if (!exception_exit_supported())
        return "this hypervisor cannot deliver exception VM exits "
               "(needs Windows 10 1803+ / a newer build)";
    return "ok";
}

} // namespace lx::runtime

#endif // _WIN32 && x86-64

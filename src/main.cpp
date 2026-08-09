#include "common.hpp"
#include "type.hpp"
#include "string.hpp"
#include "os.hpp"
#include <tl/expected.hpp>
#include <fmt/format.h>
#include <Zycore/Status.h>
#include <Zydis/Zydis.h>
#include <safetyhook/safetyhook.hpp>
#include <cstdio>
#include <utility>
#include <array>
#include <string_view>
#include <charconv>

using CreateInterfaceFn      = void *(TR_CCALL *)(cstr name, i32 *return_code);
using InstantiateInterfaceFn = void *(TR_CCALL *)();

struct edict_t;
class KeyValues;
class CCommand;

using QueryCvarCookie_t = i32;

constexpr f32 MINIMUM_TICK_INTERVAL = 0.001f;
constexpr f32 MAXIMUM_TICK_INTERVAL = 0.1f;

enum : i32
{
    IFACE_OK = 0,
    IFACE_FAILED,
};

enum PLUGIN_RESULT : i32
{
    PLUGIN_CONTINUE = 0,
    PLUGIN_OVERRIDE,
    PLUGIN_STOP,
};

enum EQueryCvarValueStatus : i32
{
    eQueryCvarValueStatus_ValueIntact = 0,
    eQueryCvarValueStatus_CvarNotFound,
    eQueryCvarValueStatus_NotACvar,
    eQueryCvarValueStatus_CvarProtected,
};

// Misc utils.
template <class... Args>
void error(fmt::format_string<Args...> fmt, Args &&...args) noexcept
{
    std::fprintf(stderr, "[Tickrate] [error] %s", fmt::format(fmt, std::forward<Args>(args)...).c_str());
    std::fflush(stderr);
}

template <class... Args>
void info(fmt::format_string<Args...> fmt, Args &&...args) noexcept
{
    std::fprintf(stdout, "[Tickrate] [info] %s", fmt::format(fmt, std::forward<Args>(args)...).c_str());
    std::fflush(stdout);
}

template <class T = u8 *>
T get_virtual(const void *object, u16 index) noexcept
{
    return (*(T **)object)[index];
}

[[nodiscard]] std::string_view safetyhookinline_error_str(const SafetyHookInline::Error &error) noexcept
{
    constexpr std::array<std::string_view, 7> strings_inline_hook = {
        "BAD_ALLOCATION",
        "FAILED_TO_DECODE_INSTRUCTION",
        "SHORT_JUMP_IN_TRAMPOLINE",
        "IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE",
        "UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE",
        "FAILED_TO_UNPROTECT",
        "NOT_ENOUGH_SPACE",
    };

    return strings_inline_hook[error.type];
}

[[nodiscard]] std::string_view zyan_status_str(ZyanStatus status) noexcept
{
    // Taken from: https://github.com/zyantific/zydis/blob/v4.1.1/tools/ZydisToolsShared.c#L79-L151
    constexpr std::array<std::string_view, 12> strings_zycore = {/* 00 */ "SUCCESS",
                                                                 /* 01 */ "FAILED",
                                                                 /* 02 */ "TRUE",
                                                                 /* 03 */ "FALSE",
                                                                 /* 04 */ "INVALID_ARGUMENT",
                                                                 /* 05 */ "INVALID_OPERATION",
                                                                 /* 06 */ "NOT_FOUND",
                                                                 /* 07 */ "OUT_OF_RANGE",
                                                                 /* 08 */ "INSUFFICIENT_BUFFER_SIZE",
                                                                 /* 09 */ "NOT_ENOUGH_MEMORY",
                                                                 /* 0A */ "NOT_ENOUGH_MEMORY",
                                                                 /* 0B */ "BAD_SYSTEMCALL"};

    constexpr std::array<std::string_view, 13> strings_zydis = {/* 00 */ "NO_MORE_DATA",
                                                                /* 01 */ "DECODING_ERROR",
                                                                /* 02 */ "INSTRUCTION_TOO_LONG",
                                                                /* 03 */ "BAD_REGISTER",
                                                                /* 04 */ "ILLEGAL_LOCK",
                                                                /* 05 */ "ILLEGAL_LEGACY_PFX",
                                                                /* 06 */ "ILLEGAL_REX",
                                                                /* 07 */ "INVALID_MAP",
                                                                /* 08 */ "MALFORMED_EVEX",
                                                                /* 09 */ "MALFORMED_MVEX",
                                                                /* 0A */ "INVALID_MASK",
                                                                /* 0B */ "SKIP_TOKEN",
                                                                /* 0C */ "IMPOSSIBLE_INSTRUCTION"};

    // if (ZYAN_STATUS_MODULE(status) >= ZYAN_MODULE_USER)
    // {
    //     return "User";
    // }

    if (ZYAN_STATUS_MODULE(status) == ZYAN_MODULE_ZYCORE)
    {
        status = ZYAN_STATUS_CODE(status);
        return status < strings_zycore.size() ? strings_zycore[status] : "";
    }

    if (ZYAN_STATUS_MODULE(status) == ZYAN_MODULE_ZYDIS)
    {
        status = ZYAN_STATUS_CODE(status);
        return status < strings_zydis.size() ? strings_zydis[status] : "";
    }

    return {};
}

struct Disasm
{
    struct Error
    {
        u8        *ip{};
        ZyanStatus status{ZYAN_STATUS_FAILED};

        [[nodiscard]] auto status_str() const noexcept
        {
            return zyan_status_str(status);
        }
    };

    u8                     *ip{};
    ZydisDecodedInstruction ix;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
};

[[nodiscard]] tl::expected<Disasm, Disasm::Error> disasm(u8 *ip, usize len = ZYDIS_MAX_INSTRUCTION_LENGTH) noexcept
{
    static ZydisDecoder decoder;
    if (static bool once{}; !once)
    {
#if TR_ARCH_X86_64
        auto status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
        auto status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
#endif
        if (ZYAN_SUCCESS(status) == ZYAN_FALSE)
        {
            return tl::unexpected{Disasm::Error{ip, status}};
        }

        once = true;
    }

    Disasm result{};
    auto   status = ZydisDecoderDecodeFull(&decoder, ip, len, &result.ix, result.operands);
    if (ZYAN_SUCCESS(status) == ZYAN_FALSE)
    {
        return tl::unexpected{Disasm::Error{ip, status}};
    }

    result.ip = ip;

    return result;
}

template <class Pred>
tl::expected<Disasm, Disasm::Error> disasm_for_each(u8 *ip, usize len, Pred &&pred) noexcept
{
    u8 *end = ip + len;

    for (u8 *i = ip; i < end;)
    {
        auto result = disasm(i, end - i);
        if (!result)
        {
            return tl::unexpected{result.error()};
        }

        auto &&value = *result;
        if (pred(value))
        {
            return value;
        }

        i += value.ix.length;
    }

    // This means we've scanned everything successfully but the predicate didn't return.
    return tl::unexpected{Disasm::Error{ip}};
}

// Engine.
class InterfaceReg
{
public:
    InstantiateInterfaceFn m_CreateFn;
    cstr                   m_pName;
    InterfaceReg          *m_pNext;
};

class CServerGameDLL
{
public:
};

// ISERVERPLUGINCALLBACKS003
class IServerPluginCallbacks
{
public:
    virtual bool          Load(CreateInterfaceFn interface_factory, CreateInterfaceFn gameserver_factory)                               = 0;
    virtual void          Unload()                                                                                                      = 0;
    virtual void          Pause()                                                                                                       = 0;
    virtual void          UnPause()                                                                                                     = 0;
    virtual cstr          GetPluginDescription()                                                                                        = 0;
    virtual void          LevelInit(cstr map_name)                                                                                      = 0;
    virtual void          ServerActivate(edict_t *edict_list, i32 edict_count, i32 client_max)                                          = 0;
    virtual void          GameFrame(bool simulating)                                                                                    = 0;
    virtual void          LevelShutdown()                                                                                               = 0;
    virtual void          ClientActive(edict_t *edict)                                                                                  = 0;
    virtual void          ClientDisconnect(edict_t *edict)                                                                              = 0;
    virtual void          ClientPutInServer(edict_t *edict, cstr player_name)                                                           = 0;
    virtual void          SetCommandClient(i32 index)                                                                                   = 0;
    virtual void          ClientSettingsChanged(edict_t *edict)                                                                         = 0;
    virtual PLUGIN_RESULT ClientConnect(bool *allow_connect, edict_t *edict, cstr name, cstr address, char *reject, i32 max_reject_len) = 0;
    virtual PLUGIN_RESULT ClientCommand(edict_t *edict, const CCommand &args)                                                           = 0;
    virtual PLUGIN_RESULT NetworkIDValidated(cstr username, cstr network_id)                                                            = 0;
    virtual void
    OnQueryCvarValueFinished(QueryCvarCookie_t cookie, edict_t *edict, EQueryCvarValueStatus status, cstr cvar_name, cstr cvar_value) = 0;
    virtual void OnEdictAllocated(edict_t *edict)                                                                                     = 0;
    virtual void OnEdictFreed(edict_t *edict)                                                                                         = 0;
};

class IGameEventListener
{
public:
    virtual ~IGameEventListener() noexcept       = default;
    virtual void FireGameEvent(KeyValues *event) = 0;
};

// Global variables, etc.
u16              g_desired_tickrate{};
SafetyHookInline g_GetTickInterval_hook{};

class Hooked_CServerGameDLL : public CServerGameDLL
{
public:
    static f32 TR_THISCALL hooked_GetTickInterval([[maybe_unused]] CServerGameDLL *instance) noexcept
    {
        f32 interval = 1.0f / (f32)g_desired_tickrate;

        return interval;
    }
};

class TickratePlugin final : public IServerPluginCallbacks,
                             public IGameEventListener
{
public:
    TickratePlugin() noexcept           = default;
    ~TickratePlugin() noexcept override = default;

    bool Load(CreateInterfaceFn interface_factory, CreateInterfaceFn gameserver_factory) noexcept override
    {
        info("Loading...\n");

        u8 *server_createinterface = (u8 *)gameserver_factory;
        u8 *server_module          = os_get_module(server_createinterface);
        if (server_module == nullptr)
        {
            error("Failed to get server module.\n");
            return false;
        }

        auto cmdline = os_get_command_line();
        if (cmdline.empty())
        {
            error("Failed to get command line.\n");
            return false;
        }

        std::string_view tickrate_value{};
        for (usize i{}; i < cmdline.size(); ++i)
        {
            // Next entry should be the value.
            if (cmdline[i] == "-tickrate" && i + 1 < cmdline.size())
            {
                tickrate_value = cmdline[i + 1];
                break;
            }
        }

        if (tickrate_value.empty())
        {
            error("Bad tickrate: Failed to find `-tickrate` command line string.\n");
            return false;
        }

        auto [ptr, ec] = std::from_chars(tickrate_value.data(), tickrate_value.data() + tickrate_value.size(), g_desired_tickrate);
        if (ec != std::errc{})
        {
            error("Bad tickrate: Failed to convert `-tickrate` command line value.\n");
            return false;
        }

        // This is not a bug. They're swapped for a reason (we convert them to an int instead of comparing the float).
        constexpr u16 min_tickrate = (u16)(1.0f / MAXIMUM_TICK_INTERVAL) + 1;
        constexpr u16 max_tickrate = (u16)(1.0f / MINIMUM_TICK_INTERVAL) + 1;

        if (g_desired_tickrate < min_tickrate)
        {
            error(
                "Bad tickrate: `-tickrate` command line value is too low (Desired tickrate is {}, minimum is {}). Server will continue with "
                "default tickrate.\n",
                g_desired_tickrate,
                min_tickrate);
            return false;
        }
        else if (g_desired_tickrate > max_tickrate)
        {
            error(
                "Bad tickrate: `-tickrate` command line value is too high (Desired tickrate is {}, maximum is {}). Server will continue with "
                "default tickrate.\n",
                g_desired_tickrate,
                max_tickrate);
            return false;
        }

        info("Desired tickrate is {}.\n", g_desired_tickrate);

        InterfaceReg *regs;

        // Check for the `s_pInterfaceRegs` symbol first.
        if (u8 *regs_symbol = os_get_procedure(server_module, "s_pInterfaceRegs"); regs_symbol != nullptr)
        {
            regs = *(InterfaceReg **)regs_symbol;
        }
        else
        {
            // No symbol was found so we have to disasm manually.
            // First we check for a jump thunk. Some versions of the game have this for some reason. If there isn't one then we don't worry about it.
            for (;;)
            {
                auto thunk_disasm_result = disasm(server_createinterface);
                if (!thunk_disasm_result)
                {
                    error("Failed to decode first instruction in `CreateInterface`: {}\n", thunk_disasm_result.error().status_str());
                    return false;
                }

                auto &&thunk_disasm = *thunk_disasm_result;
                if (thunk_disasm.ix.mnemonic != ZYDIS_MNEMONIC_JMP)
                {
                    break;
                }

                server_createinterface += thunk_disasm.ix.length + (i32)thunk_disasm.operands[0].imm.value.s;
            }

            // Find the first `mov reg, mem`.
            auto regs_disasm_result = disasm_for_each(
                server_createinterface,
                ZYDIS_MAX_INSTRUCTION_LENGTH * 25, // I hope this is enough :P
                [](auto &&result) noexcept
                {
                    // x86-64 is RIP-relative. x86-32 is absolute.
                    constexpr ZyanU16 op_size  = TR_ARCH_X86_64 == 1 ? 64 : 32;
                    constexpr auto    mem_base = TR_ARCH_X86_64 == 1 ? ZYDIS_REGISTER_RIP : ZYDIS_REGISTER_NONE;

                    return result.ix.mnemonic == ZYDIS_MNEMONIC_MOV && result.ix.operand_count_visible == 2
                        && result.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && result.operands[0].size == op_size
                        && result.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && result.operands[1].size == op_size
                        && result.operands[1].mem.segment == ZYDIS_REGISTER_DS && result.operands[1].mem.base == mem_base;
                });
            if (!regs_disasm_result)
            {
                error("Failed to find instruction containing `s_pInterfaceRegs`: {}\n", regs_disasm_result.error().status_str());
                return false;
            }

            auto &&regs_disasm = *regs_disasm_result;

            // x86-64 is RIP-relative. x86-32 is absolute.
#if TR_ARCH_X86_64
            regs = *(InterfaceReg **)(regs_disasm.ip + regs_disasm.ix.length + (i32)regs_disasm.operands[1].mem.disp.value);
#else
            regs = *(InterfaceReg **)((usize)regs_disasm.operands[1].mem.disp.value);
#endif
        }

        if (regs == nullptr)
        {
            error("Failed to find `s_pInterfaceRegs` (null).\n");
            return false;
        }

        // TODO: If this becomes an issue, we can just search for latest version... but for now, only the latest should be exist.
        CServerGameDLL *servergame{};

        for (auto *it = regs; it != nullptr; it = it->m_pNext)
        {
            if (it->m_pName == nullptr)
            {
                continue;
            }

            if (str_sv_contains(it->m_pName, "ServerGameDLL"))
            {
                servergame = (CServerGameDLL *)it->m_CreateFn();
                break;
            }
        }

        if (servergame == nullptr)
        {
            error("Failed to find `ServerGameDLL` interface.\n");
            return false;
        }

        info("Applying hooks...\n");

        // TODO: There's a chance that this virtual function might not always be index 11. Will need testing.
        u8 *fn = get_virtual(servergame, 11);

        // TODO: Switch to global VMT hooks when it's available.
        auto hook_result = safetyhook::InlineHook::create(fn, Hooked_CServerGameDLL::hooked_GetTickInterval);
        if (!hook_result)
        {
            auto &&err = hook_result.error();
            error("Failed to hook `CServerGameDLL::GetTickInterval` function: {} @ 0x{:X}\n", safetyhookinline_error_str(err), (usize)err.ip);

            return false;
        }

        g_GetTickInterval_hook = std::move(*hook_result);

        info("Loaded!\n");

        return true;
    }

    void Unload() noexcept override
    {
        g_GetTickInterval_hook = {};

        info("Unloaded.\n");
    }

    void Pause() noexcept override {}

    void UnPause() noexcept override {}

    cstr GetPluginDescription() noexcept override
    {
        return "Tickrate (angelfor3v3r)";
    }

    void LevelInit(cstr map_name) noexcept override {}

    void ServerActivate(edict_t *edict_list, i32 edict_count, i32 client_max) noexcept override {}

    void GameFrame(bool simulating) noexcept override {}

    void LevelShutdown() noexcept override {}

    void ClientActive(edict_t *edict) noexcept override {}

    void ClientDisconnect(edict_t *edict) noexcept override {}

    void ClientPutInServer(edict_t *edict, cstr player_name) noexcept override {}

    void SetCommandClient(i32 index) noexcept override {}

    void ClientSettingsChanged(edict_t *edict) noexcept override {}

    PLUGIN_RESULT
    ClientConnect(bool *allow_connect, edict_t *edict, cstr name, cstr address, char *reject, i32 max_reject_len) noexcept override
    {
        return PLUGIN_CONTINUE;
    }

    PLUGIN_RESULT ClientCommand(edict_t *edict, const CCommand &args) noexcept override
    {
        return PLUGIN_CONTINUE;
    }

    PLUGIN_RESULT NetworkIDValidated(cstr username, cstr network_id) noexcept override
    {
        return PLUGIN_CONTINUE;
    }

    void OnQueryCvarValueFinished(
        QueryCvarCookie_t cookie, edict_t *edict, EQueryCvarValueStatus status, cstr cvar_name, cstr cvar_value) noexcept override
    {}

    void OnEdictAllocated(edict_t *edict) noexcept override {}

    void OnEdictFreed(edict_t *edict) noexcept override {}

    void FireGameEvent(KeyValues *event) noexcept override {}
};

TickratePlugin g_tickrate_plugin{};

extern "C" TR_DLLEXPORT void *CreateInterface(cstr name, i32 *return_code) noexcept
{
    TickratePlugin *result{};

    // First call should be the latest version.
    // v2 added `OnQueryCvarValueFinished`.
    // v3 added `OnEdictAllocated`/`OnEdictFreed`.
    if (str_sv_contains(name, "ISERVERPLUGINCALLBACKS"))
    {
        result = &g_tickrate_plugin;
    }

    if (return_code != nullptr)
    {
        *return_code = result != nullptr ? IFACE_OK : IFACE_FAILED;
    }

    return result;
}

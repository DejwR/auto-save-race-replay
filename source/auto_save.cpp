#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

// ABI prefix from the public Swofty SDK. Only the event and logging entries
// are used here. The opaque entries retain the position of the events table.
struct SwoftyEvent;
using EventCallback = void (*)(const SwoftyEvent*, void*);

struct SwoftyEvents {
    int (*available)();
    int (*subscribe)(const char*, EventCallback, void*, std::uint32_t*);
    int (*on_frame)(void (*)(double, void*), void*, std::uint32_t*);
    int (*unsubscribe)(std::uint32_t);
};

struct SwoftyApi {
    std::uint32_t version;
    void (*log)(const char*, ...);
    std::uintptr_t (*module_base)();
    void* unused[7];
    const SwoftyEvents* events;
};

static_assert(offsetof(SwoftyApi, events) == 80);

namespace {

constexpr DWORD kExpectedTimestamp = 0x6aa3c898;
constexpr DWORD kExpectedImageSize = 0x193e6000;
constexpr std::uintptr_t kResultsVtable = 0x574ba80;
constexpr std::uintptr_t kActivateSlot = 0x574bae8;
constexpr std::uintptr_t kActivate = 0x1d8f9f0;
constexpr std::uintptr_t kResultsAction = 0x1d92230;
constexpr std::uintptr_t kSaveActionBranch = 0x1d92285;
constexpr std::uint32_t kSaveFullReplayAction = 0x505aa8b2;
constexpr std::size_t kReplaySystem = 0x2f0;
constexpr std::size_t kReplaySaveAllowed = 0x6e1;
constexpr std::size_t kReplayJob = 0x150;
constexpr int kEventOk = 0;

using Activate = std::uintptr_t (*)(void*, std::uintptr_t, std::uintptr_t, std::uintptr_t);
using ResultsAction = void (*)(void*, const std::uint32_t* const*, void*, void*);

const SwoftyApi* g_api = nullptr;
std::uintptr_t g_base = 0;
std::atomic_bool g_race_pending{false};

bool IsSupportedBuild(std::uintptr_t base) {
    if (!base) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        dos->e_lfanew > 0x800) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->FileHeader.TimeDateStamp != kExpectedTimestamp ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.SizeOfImage != kExpectedImageSize) return false;

    constexpr std::uint8_t activate_start[] = {
        0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 0x55, 0x53,
        0x48, 0x81, 0xec, 0xe8, 0x00, 0x00, 0x00, 0x48, 0x89, 0xce,
    };
    // cmp eax, save action; jne end; load the replay system from the view model.
    constexpr std::uint8_t action_branch[] = {
        0x3d, 0xb2, 0xa8, 0x5a, 0x50, 0x0f, 0x85, 0x17, 0x0c, 0x00, 0x00,
        0x48, 0x8b, 0xb6, 0xf0, 0x02, 0x00, 0x00,
        0x80, 0xbe, 0xe1, 0x06, 0x00, 0x00, 0x00,
    };
    return std::memcmp(reinterpret_cast<const void*>(base + kActivate),
                       activate_start, sizeof(activate_start)) == 0 &&
           std::memcmp(reinterpret_cast<const void*>(base + kSaveActionBranch - 11),
                       action_branch, sizeof(action_branch)) == 0 &&
           *reinterpret_cast<const std::uintptr_t*>(base + kActivateSlot) == base + kActivate;
}

void ResetRace(const SwoftyEvent*, void*) {
    g_race_pending.store(false);
}

void ArmRace(const SwoftyEvent*, void*) {
    g_race_pending.store(true);
    g_api->log("[auto-save-race-replay] race started; armed for results");
}

std::uintptr_t OnResultsActivated(void* model, std::uintptr_t arg2, std::uintptr_t arg3,
                                  std::uintptr_t arg4) {
    const auto original = reinterpret_cast<Activate>(g_base + kActivate);
    const auto result = original(model, arg2, arg3, arg4);
    if (!g_race_pending.load()) return result;

    const auto* view = static_cast<const std::uint8_t*>(model);
    if (*reinterpret_cast<const std::uintptr_t*>(view) != g_base + kResultsVtable) return result;
    const auto* replay = *reinterpret_cast<const std::uint8_t* const*>(view + kReplaySystem);
    if (!replay || !replay[kReplaySaveAllowed] ||
        !*reinterpret_cast<const void* const*>(replay + kReplayJob)) {
        g_api->log("[auto-save-race-replay] results opened; game replay is unavailable");
        return result;
    }
    if (!g_race_pending.exchange(false)) return result;

    // The selected branch reads only the hash at the first pointer's target.
    const std::uint32_t* command = &kSaveFullReplayAction;
    const auto dispatch = reinterpret_cast<ResultsAction>(g_base + kResultsAction);
    g_api->log("[auto-save-race-replay] requesting full replay from race results");
    dispatch(model, &command, nullptr, nullptr);
    return result;
}

bool InstallResultsHook() {
    auto* slot = reinterpret_cast<void* volatile*>(g_base + kActivateSlot);
    auto* expected = reinterpret_cast<void*>(g_base + kActivate);
    auto* hook = reinterpret_cast<void*>(&OnResultsActivated);
    DWORD old_protection = 0;
    if (!VirtualProtect(const_cast<void**>(slot), sizeof(*slot), PAGE_READWRITE, &old_protection)) {
        return false;
    }
    const auto previous = InterlockedCompareExchangePointer(slot, hook, expected);
    DWORD ignored = 0;
    if (!VirtualProtect(const_cast<void**>(slot), sizeof(*slot), old_protection, &ignored)) {
        if (previous == expected) InterlockedCompareExchangePointer(slot, expected, hook);
        return false;
    }
    return previous == expected;
}

} // namespace

extern "C" __declspec(dllexport) const std::uint32_t SwoftyAddonApi = 8;

extern "C" __declspec(dllexport) int SwoftyAddonInit(const SwoftyApi* api) {
    if (!api || api->version < 5 || !api->log || !api->module_base || !api->events) return 0;
    const auto base = api->module_base();
    if (!IsSupportedBuild(base) || g_api) {
        api->log("[auto-save-race-replay] unsupported or already hooked; autosave disabled");
        return 0;
    }

    const auto* events = api->events;
    if (!events->available || !events->subscribe || !events->available()) {
        api->log("[auto-save-race-replay] Swofty events unavailable; autosave disabled");
        return 0;
    }
    g_api = api;
    g_base = base;
    if (events->subscribe("session.start", ResetRace, nullptr, nullptr) != kEventOk ||
        events->subscribe("session.unload", ResetRace, nullptr, nullptr) != kEventOk ||
        events->subscribe("race.start", ArmRace, nullptr, nullptr) != kEventOk ||
        !InstallResultsHook()) {
        // Swofty removes event subscriptions when init fails.
        g_api = nullptr;
        g_base = 0;
        api->log("[auto-save-race-replay] could not arm results hook; autosave disabled");
        return 0;
    }
    api->log("[auto-save-race-replay] ready; waiting for an offline race");
    return 1;
}

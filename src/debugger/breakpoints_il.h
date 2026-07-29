// Copyright (c) 2026 XDX
// Distributed under the MIT License.

#pragma once

#include "cor.h"
#include "cordebug.h"

#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "interfaces/idebugger.h"
#include "utils/torelease.h"

namespace netcoredbg
{

class Modules;
class Variables;

class IlBreakpoints
{
public:
    IlBreakpoints(std::shared_ptr<Modules> &sharedModules, std::shared_ptr<Variables> &sharedVariables) :
        m_sharedModules(sharedModules),
        m_sharedVariables(sharedVariables)
    {}

    void DeleteAll();
    HRESULT SetIlBreakpoints(bool haveProcess,
                             const std::vector<IlBreakpoint> &ilBreakpoints,
                             std::vector<IlBreakpointBinding> &bindings,
                             std::function<uint32_t()> getId);
    HRESULT AllBreakpointsActivate(bool act);
    HRESULT BreakpointActivate(uint32_t id, bool act);
    void AddAllBreakpointsInfo(std::vector<IDebugger::BreakpointInfo> &list);

    // S_OK means this IL breakpoint was hit. S_FALSE means it was not.
    HRESULT CheckBreakpointHit(ICorDebugThread *pThread,
                               ICorDebugBreakpoint *pBreakpoint,
                               Breakpoint &breakpoint,
                               std::vector<BreakpointEvent> &bpChangeEvents);

    HRESULT ManagedCallbackLoadModule(ICorDebugModule *pModule,
                                      std::vector<IlBreakpointBinding> &changes);
    HRESULT ManagedCallbackUnloadModule(ICorDebugModule *pModule,
                                        std::vector<IlBreakpointBinding> &changes);
    HRESULT UpdateBreakpointsOnHotReload(ICorDebugModule *pModule,
                                         const std::unordered_set<mdMethodDef> &methodTokens,
                                         std::vector<IlBreakpointBinding> &changes);

private:
    struct InternalBreakpoint
    {
        CORDB_ADDRESS moduleAddress;
        ULONG32 methodVersion;
        ULONG32 ilOffset;
        ToRelease<ICorDebugFunctionBreakpoint> breakpoint;

        InternalBreakpoint(CORDB_ADDRESS moduleAddress,
                           ULONG32 methodVersion,
                           ULONG32 ilOffset,
                           ICorDebugFunctionBreakpoint *breakpoint) :
            moduleAddress(moduleAddress),
            methodVersion(methodVersion),
            ilOffset(ilOffset),
            breakpoint(breakpoint)
        {}

        InternalBreakpoint(InternalBreakpoint &&that) = default;
        InternalBreakpoint(const InternalBreakpoint &that) = delete;
        InternalBreakpoint& operator=(InternalBreakpoint &&that) = default;
        InternalBreakpoint& operator=(const InternalBreakpoint &that) = delete;
    };

    struct ManagedIlBreakpoint
    {
        uint32_t internalId;
        std::string id;
        std::string moduleMvid;
        mdMethodDef methodToken;
        ULONG32 requestedIlOffset;
        bool enabled;
        std::string condition;
        std::string hitCondition;
        std::string logMessage;
        ULONG32 times;
        bool moduleSeen;
        std::string message;
        std::list<InternalBreakpoint> breakpoints;

        ManagedIlBreakpoint() :
            internalId(0),
            methodToken(0),
            requestedIlOffset(0),
            enabled(true),
            times(0),
            moduleSeen(false)
        {}

        ~ManagedIlBreakpoint();
        bool IsVerified() const;
        bool SameLocation(const IlBreakpoint &breakpoint) const;
        void ToBinding(IlBreakpointBinding &binding) const;

        ManagedIlBreakpoint(ManagedIlBreakpoint &&that) = default;
        ManagedIlBreakpoint(const ManagedIlBreakpoint &that) = delete;
        ManagedIlBreakpoint& operator=(ManagedIlBreakpoint &&that) = default;
        ManagedIlBreakpoint& operator=(const ManagedIlBreakpoint &that) = delete;
    };

    std::shared_ptr<Modules> m_sharedModules;
    std::shared_ptr<Variables> m_sharedVariables;
    std::mutex m_breakpointsMutex;
    std::unordered_map<std::string, ManagedIlBreakpoint> m_breakpoints;

    static std::string NormalizeMvid(std::string mvid);
    static void DeactivateAndClear(ManagedIlBreakpoint &breakpoint);
    HRESULT ResolveBreakpoint(ManagedIlBreakpoint &breakpoint);
    HRESULT BindBreakpointInModule(ICorDebugModule *pModule, ManagedIlBreakpoint &breakpoint);
};

} // namespace netcoredbg

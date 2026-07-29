// Copyright (c) 2026 XDX
// Distributed under the MIT License.

#include "debugger/breakpoints_il.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include "debugger/breakpointutils.h"
#include "debugger/variables.h"
#include "metadata/modules.h"

namespace netcoredbg
{

IlBreakpoints::ManagedIlBreakpoint::~ManagedIlBreakpoint()
{
    for (auto &entry : breakpoints)
    {
        if (entry.breakpoint)
            entry.breakpoint->Activate(FALSE);
    }
}

bool IlBreakpoints::ManagedIlBreakpoint::IsVerified() const
{
    return enabled &&
           hitCondition.empty() &&
           logMessage.empty() &&
           !breakpoints.empty();
}

bool IlBreakpoints::ManagedIlBreakpoint::SameLocation(const IlBreakpoint &breakpoint) const
{
    return moduleMvid == NormalizeMvid(breakpoint.moduleMvid) &&
           methodToken == breakpoint.methodToken &&
           requestedIlOffset == breakpoint.ilOffset;
}

void IlBreakpoints::ManagedIlBreakpoint::ToBinding(IlBreakpointBinding &binding) const
{
    binding.id = id;
    binding.verified = IsVerified();
    binding.moduleMvid = moduleMvid;
    binding.methodToken = methodToken;
    binding.ilOffset = breakpoints.empty() ? requestedIlOffset : breakpoints.front().ilOffset;

    if (!enabled)
        binding.message = "Breakpoint is disabled.";
    else if (!hitCondition.empty())
        binding.message = "IL breakpoint hit conditions are not supported.";
    else if (!logMessage.empty())
        binding.message = "IL breakpoint log messages are not supported.";
    else if (binding.verified)
        binding.message.clear();
    else if (!message.empty())
        binding.message = message;
    else if (!moduleSeen)
        binding.message = "Pending: module is not loaded.";
    else
        binding.message = "Method token or IL offset could not be bound.";
}

std::string IlBreakpoints::NormalizeMvid(std::string mvid)
{
    std::transform(mvid.begin(), mvid.end(), mvid.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return mvid;
}

void IlBreakpoints::DeactivateAndClear(ManagedIlBreakpoint &breakpoint)
{
    for (auto &entry : breakpoint.breakpoints)
    {
        if (entry.breakpoint)
            entry.breakpoint->Activate(FALSE);
    }
    breakpoint.breakpoints.clear();
}

void IlBreakpoints::DeleteAll()
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);
    m_breakpoints.clear();
}

HRESULT IlBreakpoints::BindBreakpointInModule(ICorDebugModule *pModule,
                                               ManagedIlBreakpoint &breakpoint)
{
    HRESULT Status;
    std::string moduleMvid;
    IfFailRet(GetModuleId(pModule, moduleMvid));
    if (NormalizeMvid(moduleMvid) != breakpoint.moduleMvid)
        return S_FALSE;

    breakpoint.moduleSeen = true;

    CORDB_ADDRESS moduleAddress;
    IfFailRet(pModule->GetBaseAddress(&moduleAddress));
    auto existing = std::find_if(
        breakpoint.breakpoints.begin(),
        breakpoint.breakpoints.end(),
        [moduleAddress](const InternalBreakpoint &entry) {
            return entry.moduleAddress == moduleAddress;
        });
    if (existing != breakpoint.breakpoints.end())
        return S_OK;

    ToRelease<ICorDebugFunction> function;
    Status = pModule->GetFunctionFromToken(breakpoint.methodToken, &function);
    if (FAILED(Status))
    {
        breakpoint.message = "MethodDef token was not found in the loaded module.";
        return S_FALSE;
    }

    ULONG32 methodVersion;
    Status = function->GetCurrentVersionNumber(&methodVersion);
    if (FAILED(Status))
    {
        breakpoint.message = "Could not read the method code version.";
        return S_FALSE;
    }

    ToRelease<ICorDebugCode> code;
    Status = function->GetILCode(&code);
    if (FAILED(Status))
    {
        breakpoint.message = "Method has no debuggable IL body.";
        return S_FALSE;
    }

    ULONG32 codeSize;
    Status = code->GetSize(&codeSize);
    if (FAILED(Status) || breakpoint.requestedIlOffset >= codeSize)
    {
        breakpoint.message = "IL offset is outside the method body.";
        return S_FALSE;
    }

    ToRelease<ICorDebugFunctionBreakpoint> functionBreakpoint;
    Status = code->CreateBreakpoint(
        breakpoint.requestedIlOffset,
        &functionBreakpoint);
    if (FAILED(Status))
    {
        breakpoint.message = "IL offset is not a valid breakpoint location.";
        return S_FALSE;
    }

    ULONG32 actualOffset = breakpoint.requestedIlOffset;
    functionBreakpoint->GetOffset(&actualOffset);
    Status = functionBreakpoint->Activate(breakpoint.enabled ? TRUE : FALSE);
    if (FAILED(Status))
    {
        breakpoint.message = "Could not activate the IL breakpoint.";
        return S_FALSE;
    }

    breakpoint.breakpoints.emplace_back(
        moduleAddress,
        methodVersion,
        actualOffset,
        functionBreakpoint.Detach());
    breakpoint.message.clear();
    return S_OK;
}

HRESULT IlBreakpoints::ResolveBreakpoint(ManagedIlBreakpoint &breakpoint)
{
    breakpoint.moduleSeen = false;
    breakpoint.message.clear();

    if (!breakpoint.hitCondition.empty() || !breakpoint.logMessage.empty())
        return S_OK;

    return m_sharedModules->ForEachModule(
        [&](ICorDebugModule *pModule) -> HRESULT {
            HRESULT bindStatus = BindBreakpointInModule(pModule, breakpoint);
            return FAILED(bindStatus) ? bindStatus : S_OK;
        });
}

HRESULT IlBreakpoints::SetIlBreakpoints(
    bool haveProcess,
    const std::vector<IlBreakpoint> &ilBreakpoints,
    std::vector<IlBreakpointBinding> &bindings,
    std::function<uint32_t()> getId)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);

    std::unordered_set<std::string> requestedIds;
    for (const auto &requested : ilBreakpoints)
    {
        if (!requestedIds.insert(requested.id).second)
            return E_INVALIDARG;
    }

    for (auto it = m_breakpoints.begin(); it != m_breakpoints.end();)
    {
        if (requestedIds.find(it->first) == requestedIds.end())
            it = m_breakpoints.erase(it);
        else
            ++it;
    }

    bindings.reserve(ilBreakpoints.size());
    for (const auto &requested : ilBreakpoints)
    {
        auto existing = m_breakpoints.find(requested.id);
        if (existing != m_breakpoints.end() &&
            !existing->second.SameLocation(requested))
        {
            m_breakpoints.erase(existing);
            existing = m_breakpoints.end();
        }

        if (existing == m_breakpoints.end())
        {
            ManagedIlBreakpoint breakpoint;
            breakpoint.internalId = getId();
            breakpoint.id = requested.id;
            breakpoint.moduleMvid = NormalizeMvid(requested.moduleMvid);
            breakpoint.methodToken = requested.methodToken;
            breakpoint.requestedIlOffset = requested.ilOffset;
            breakpoint.enabled = requested.enabled;
            breakpoint.condition = requested.condition;
            breakpoint.hitCondition = requested.hitCondition;
            breakpoint.logMessage = requested.logMessage;
            if (haveProcess)
                ResolveBreakpoint(breakpoint);
            existing = m_breakpoints.emplace(
                requested.id,
                std::move(breakpoint)).first;
        }
        else
        {
            ManagedIlBreakpoint &breakpoint = existing->second;
            breakpoint.condition = requested.condition;
            breakpoint.hitCondition = requested.hitCondition;
            breakpoint.logMessage = requested.logMessage;
            breakpoint.enabled = requested.enabled;

            if (!breakpoint.hitCondition.empty() ||
                !breakpoint.logMessage.empty())
            {
                DeactivateAndClear(breakpoint);
            }
            else
            {
                for (auto &entry : breakpoint.breakpoints)
                {
                    if (entry.breakpoint)
                        entry.breakpoint->Activate(
                            requested.enabled ? TRUE : FALSE);
                }
                if (haveProcess && breakpoint.breakpoints.empty())
                    ResolveBreakpoint(breakpoint);
            }
        }

        IlBreakpointBinding binding;
        existing->second.ToBinding(binding);
        bindings.emplace_back(std::move(binding));
    }

    return S_OK;
}

HRESULT IlBreakpoints::ManagedCallbackLoadModule(
    ICorDebugModule *pModule,
    std::vector<IlBreakpointBinding> &changes)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);
    for (auto &pair : m_breakpoints)
    {
        IlBreakpointBinding before;
        pair.second.ToBinding(before);
        HRESULT Status = BindBreakpointInModule(pModule, pair.second);
        if (FAILED(Status))
            return Status;
        IlBreakpointBinding after;
        pair.second.ToBinding(after);
        if (before.verified != after.verified ||
            before.ilOffset != after.ilOffset ||
            before.message != after.message)
            changes.emplace_back(std::move(after));
    }
    return S_OK;
}

HRESULT IlBreakpoints::ManagedCallbackUnloadModule(
    ICorDebugModule *pModule,
    std::vector<IlBreakpointBinding> &changes)
{
    HRESULT Status;
    CORDB_ADDRESS moduleAddress;
    IfFailRet(pModule->GetBaseAddress(&moduleAddress));

    std::lock_guard<std::mutex> lock(m_breakpointsMutex);
    for (auto &pair : m_breakpoints)
    {
        ManagedIlBreakpoint &breakpoint = pair.second;
        IlBreakpointBinding before;
        breakpoint.ToBinding(before);
        for (auto it = breakpoint.breakpoints.begin();
             it != breakpoint.breakpoints.end();)
        {
            if (it->moduleAddress != moduleAddress)
            {
                ++it;
                continue;
            }

            if (it->breakpoint)
                it->breakpoint->Activate(FALSE);
            it = breakpoint.breakpoints.erase(it);
        }
        if (breakpoint.breakpoints.empty())
        {
            breakpoint.moduleSeen = false;
            breakpoint.message.clear();
        }
        IlBreakpointBinding after;
        breakpoint.ToBinding(after);
        if (before.verified != after.verified ||
            before.ilOffset != after.ilOffset ||
            before.message != after.message)
            changes.emplace_back(std::move(after));
    }
    return S_OK;
}

HRESULT IlBreakpoints::UpdateBreakpointsOnHotReload(
    ICorDebugModule *pModule,
    const std::unordered_set<mdMethodDef> &methodTokens,
    std::vector<IlBreakpointBinding> &changes)
{
    HRESULT Status;
    CORDB_ADDRESS moduleAddress;
    IfFailRet(pModule->GetBaseAddress(&moduleAddress));

    std::lock_guard<std::mutex> lock(m_breakpointsMutex);
    for (auto &pair : m_breakpoints)
    {
        ManagedIlBreakpoint &breakpoint = pair.second;
        if (methodTokens.find(breakpoint.methodToken) == methodTokens.end())
            continue;
        IlBreakpointBinding before;
        breakpoint.ToBinding(before);

        for (auto it = breakpoint.breakpoints.begin();
             it != breakpoint.breakpoints.end();)
        {
            if (it->moduleAddress != moduleAddress)
            {
                ++it;
                continue;
            }
            if (it->breakpoint)
                it->breakpoint->Activate(FALSE);
            it = breakpoint.breakpoints.erase(it);
        }

        Status = BindBreakpointInModule(pModule, breakpoint);
        if (FAILED(Status))
            return Status;
        IlBreakpointBinding after;
        breakpoint.ToBinding(after);
        if (before.verified != after.verified ||
            before.ilOffset != after.ilOffset ||
            before.message != after.message)
            changes.emplace_back(std::move(after));
    }
    return S_OK;
}

HRESULT IlBreakpoints::CheckBreakpointHit(
    ICorDebugThread *pThread,
    ICorDebugBreakpoint *pBreakpoint,
    Breakpoint &breakpoint,
    std::vector<BreakpointEvent> &bpChangeEvents)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);
    if (m_breakpoints.empty())
        return S_FALSE;

    HRESULT Status;
    ToRelease<ICorDebugFunctionBreakpoint> functionBreakpoint;
    IfFailRet(pBreakpoint->QueryInterface(
        IID_ICorDebugFunctionBreakpoint,
        reinterpret_cast<LPVOID*>(&functionBreakpoint)));

    for (auto &pair : m_breakpoints)
    {
        ManagedIlBreakpoint &managed = pair.second;
        if (!managed.enabled)
            continue;

        for (auto &entry : managed.breakpoints)
        {
            IfFailRet(BreakpointUtils::IsSameFunctionBreakpoint(
                functionBreakpoint,
                entry.breakpoint));
            if (Status == S_FALSE)
                continue;

            std::string output;
            Status = BreakpointUtils::IsEnableByCondition(
                managed.condition,
                m_sharedVariables.get(),
                pThread,
                output);
            if (FAILED(Status) && output.empty())
                return Status;
            if (Status == S_FALSE)
                continue;

            ++managed.times;
            breakpoint.id = managed.internalId;
            breakpoint.verified = true;
            breakpoint.condition = managed.condition;
            breakpoint.module = managed.moduleMvid;
            std::ostringstream name;
            name << "0x" << std::hex << managed.methodToken
                 << " IL_"
                 << std::setfill('0') << std::setw(4)
                 << entry.ilOffset;
            breakpoint.funcname = name.str();

            if (!output.empty())
            {
                breakpoint.message =
                    "The condition for an IL breakpoint failed to execute. "
                    "The condition was '" + managed.condition +
                    "'. The error returned was '" + output + "'.";
                bpChangeEvents.emplace_back(
                    BreakpointChanged,
                    breakpoint);
            }
            return S_OK;
        }
    }

    return S_FALSE;
}

HRESULT IlBreakpoints::AllBreakpointsActivate(bool act)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);
    HRESULT result = S_OK;
    for (auto &pair : m_breakpoints)
    {
        pair.second.enabled = act;
        for (auto &entry : pair.second.breakpoints)
        {
            HRESULT status = entry.breakpoint->Activate(act ? TRUE : FALSE);
            if (FAILED(status))
                result = status;
        }
    }
    return result;
}

HRESULT IlBreakpoints::BreakpointActivate(uint32_t id, bool act)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);
    for (auto &pair : m_breakpoints)
    {
        ManagedIlBreakpoint &breakpoint = pair.second;
        if (breakpoint.internalId != id)
            continue;

        HRESULT result = S_OK;
        breakpoint.enabled = act;
        for (auto &entry : breakpoint.breakpoints)
        {
            HRESULT status = entry.breakpoint->Activate(act ? TRUE : FALSE);
            if (FAILED(status))
                result = status;
        }
        return result;
    }
    return E_FAIL;
}

void IlBreakpoints::AddAllBreakpointsInfo(
    std::vector<IDebugger::BreakpointInfo> &list)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);
    list.reserve(list.size() + m_breakpoints.size());
    for (const auto &pair : m_breakpoints)
    {
        const ManagedIlBreakpoint &breakpoint = pair.second;
        std::ostringstream name;
        name << "0x" << std::hex << breakpoint.methodToken
             << " IL_"
             << std::setfill('0') << std::setw(4)
             << breakpoint.requestedIlOffset;
        list.emplace_back(IDebugger::BreakpointInfo{
            breakpoint.internalId,
            breakpoint.IsVerified(),
            breakpoint.enabled,
            breakpoint.times,
            breakpoint.condition,
            name.str(),
            0,
            0,
            breakpoint.moduleMvid,
            std::string()});
    }
}

} // namespace netcoredbg

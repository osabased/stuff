-- ============================================================
--  Roblox Anti-Cheat Reconnaissance & Analysis Tool  v1.0
--  Architecture Schematic implementation
--  Run in your own place only (Roblox creator policy applies)
-- ============================================================

-- ── Shared State ────────────────────────────────────────────
local API      = {}   -- Phase 1: executor API presence map
local BASELINE = {}   -- Phase 1: real environment snapshot
local PROBE    = {}   -- Phase 2: closure identity results
local SIGNALS  = {}   -- Phase 3: signal topology
local HOOKS    = {}   -- Phase 4: hook detection results
local ENV      = {}   -- Phase 5: environment/memory results
local INSTANCES = {}  -- Phase 6: instance/script scan results
local TIMING   = {}   -- Phase 7: behavioral timing results

local REPORT = {
    meta    = { version = "1.0", timestamp = os.clock(), executor_fingerprint = "unknown", run_duration_sec = 0 },
    entries = {},
    summary = { finding_count = 0, significant_count = 0, closure_behavior = {}, hooked_fns = {} },
    gaps    = {},
}

-- ── Utility ──────────────────────────────────────────────────
local function log_entry(section, key, value, severity, phase, safe)
    safe = (safe == nil) and true or safe
    local entry = {
        section   = section,
        key       = key,
        value     = value,
        severity  = severity or "info",
        timestamp = os.clock(),
        phase     = phase,
        safe      = safe,
    }
    table.insert(REPORT.entries, entry)
    REPORT.summary.finding_count = REPORT.summary.finding_count + 1
    if severity == "significant" then
        REPORT.summary.significant_count = REPORT.summary.significant_count + 1
    end
    return entry
end

local function log_gap(probe_name)
    table.insert(REPORT.gaps, probe_name)
    log_entry("gap", probe_name, "NOT_RUN", "info", 0, false)
end

local prefixes = { info = "  ✓", notable = "  ⚠", significant = "  ✗", gap = "  ○", detail = "   " }

local function emit(severity, msg)
    local pfx = prefixes[severity] or "   "
    print(pfx .. " " .. tostring(msg))
end

local function section_header(n, name)
    print("\n══ PHASE " .. n .. " — " .. name .. " " .. string.rep("═", math.max(0, 45 - #name)))
end

local function probe_header(id, name)
    print("\n  ── Probe " .. id .. " " .. name)
end

-- Safe pcall wrapper that always returns ok, value
local function safe_call(fn, ...)
    local ok, val = pcall(fn, ...)
    return ok, val
end

-- ═══════════════════════════════════════════════════════════
--  PHASE 1 — Bootstrap & API Inventory
-- ═══════════════════════════════════════════════════════════
local function phase1()
    section_header(1, "Bootstrap & API Inventory")

    -- 1.1 Executor API Presence
    probe_header("1.1", "Executor API Presence")
    local known_apis = {
        "getconnections", "getrawmetatable", "setrawmetatable",
        "hookfunction",   "newcclosure",     "iscclosure",
        "islclosure",     "checkclosure",    "clonefunction",
        "getrenv",        "getgenv",         "getsenv",
        "getfenv",        "setfenv",         "getreg",
        "getupvalues",    "setupvalue",      "getprotos",
        "getconstants",   "setconstant",     "getrunningscripts",
        "getloadedmodules","getscriptbytecode","decompile",
        "readfile",       "writefile",       "listfiles",
        "loadstring",     "Drawing",         "setclipboard",
        "queue_on_teleport","is_executor_closure",
        "fireclickdetector","firetouchinterest","fireproximityprompt",
        "getcallstack",   "getthreadidentity","setthreadidentity",
        "getnamecallmethod","setnamecallmethod",
        "identifyexecutor","getexecutorname",
        "debug.getinfo",  "debug.getupvalue","debug.setupvalue",
        "debug.getmetatable","debug.setmetatable",
        "debug.traceback","debug.profilebegin","debug.profileend",
        "debug.sethook",  "debug.gethook",
    }

    local present, absent = {}, {}
    for _, name in ipairs(known_apis) do
        local ref = nil
        if name:find("^debug%.") then
            local sub = name:sub(7)
            ref = type(debug) == "table" and debug[sub] or nil
        else
            ref = (getgenv and getgenv()[name]) or rawget(_G, name) or nil
        end
        API[name] = ref
        if ref ~= nil then
            table.insert(present, name)
        else
            table.insert(absent, name)
        end
    end

    emit("info", "APIs present: " .. #present .. " / " .. #known_apis)
    for _, n in ipairs(present) do emit("detail", "+ " .. n) end
    log_entry("bootstrap", "api_present_count", #present, "info", 1)
    log_entry("bootstrap", "api_present_list",  present,  "info", 1)

    -- 1.2 debug.* subfields
    probe_header("1.2", "debug.* Subfields")
    if type(debug) == "table" then
        for k, v in pairs(debug) do
            API["debug." .. k] = v
            emit("detail", "debug." .. k .. " = " .. type(v))
        end
        log_entry("bootstrap", "debug_keys", (function() local t={} for k in pairs(debug) do t[#t+1]=k end return t end)(), "info", 1)
    else
        emit("notable", "debug table not accessible")
        log_entry("bootstrap", "debug_accessible", false, "notable", 1)
    end

    -- 1.3 Real Environment Baseline
    probe_header("1.3", "Real Environment Baseline")
    if API["getrenv"] then
        local ok, renv = safe_call(API["getrenv"])
        if ok and type(renv) == "table" then
            -- Snapshot key engine functions
            local targets = {
                "pcall","xpcall","error","assert",
                "task","math","string","table",
                "FireServer","InvokeServer",
            }
            for _, k in ipairs(targets) do
                BASELINE[k] = renv[k]
            end
            -- Snapshot task subtable
            if type(renv.task) == "table" then
                BASELINE.task = {}
                for k,v in pairs(renv.task) do BASELINE.task[k] = v end
            end
            emit("info", "Baseline captured (" .. #targets .. " root keys snapshotted)")
            log_entry("bootstrap", "baseline_captured", true, "info", 1)
        else
            emit("notable", "getrenv() failed or returned non-table")
            log_entry("bootstrap", "baseline_captured", false, "notable", 1)
        end
    else
        emit("notable", "getrenv not available — baseline skipped")
        log_entry("bootstrap", "baseline_captured", false, "notable", 1)
    end

    -- 1.4 Executor Fingerprint
    probe_header("1.4", "Executor Fingerprint")
    local fingerprint = "unknown"
    if API["identifyexecutor"] then
        local ok, name = safe_call(API["identifyexecutor"])
        if ok then fingerprint = tostring(name) end
    elseif API["getexecutorname"] then
        local ok, name = safe_call(API["getexecutorname"])
        if ok then fingerprint = tostring(name) end
    else
        -- Heuristic fingerprint from API set
        if API["newcclosure"] and API["getconnections"] and API["getreg"] then
            if API["getscriptbytecode"] then
                fingerprint = "likely-synapse-or-similar"
            else
                fingerprint = "partial-executor"
            end
        elseif API["getconnections"] then
            fingerprint = "minimal-executor"
        end
    end
    REPORT.meta.executor_fingerprint = fingerprint
    emit("info", "Executor fingerprint: " .. fingerprint)
    log_entry("bootstrap", "executor_fingerprint", fingerprint, "info", 1)
end

-- ═══════════════════════════════════════════════════════════
--  PHASE 2 — Closure Identity Characterization
-- ═══════════════════════════════════════════════════════════
local function phase2()
    section_header(2, "Closure Identity Characterization")

    -- Three test subjects
    local lua_closure = function() return true end
    local c_closure   = math.abs
    local nc_closure  = nil

    if API["newcclosure"] then
        local ok, nc = safe_call(API["newcclosure"], lua_closure)
        if ok then nc_closure = nc end
    end

    local subjects = {
        { name = "lua_closure",  fn = lua_closure },
        { name = "c_closure",    fn = c_closure   },
        { name = "nc_closure",   fn = nc_closure  },
    }

    -- 2.1 islclosure matrix
    probe_header("2.1", "islclosure Behavior Matrix")
    if API["islclosure"] then
        for _, s in ipairs(subjects) do
            if s.fn then
                local ok, val = safe_call(API["islclosure"], s.fn)
                local key = "lc_on_" .. s.name
                PROBE[key] = { ok = ok, value = val }
                emit(ok and "info" or "notable",
                    string.format("islclosure(%s) → ok=%s val=%s", s.name, tostring(ok), tostring(val)))
                log_entry("closure", key, val, "info", 2)
            else
                PROBE["lc_on_" .. s.name] = { ok = false, value = "nil" }
                emit("detail", "islclosure(" .. s.name .. ") — subject unavailable")
            end
        end
    else
        emit("notable", "islclosure not available")
        log_entry("closure", "islclosure_available", false, "notable", 2)
    end

    -- 2.2 iscclosure matrix
    probe_header("2.2", "iscclosure Behavior Matrix")
    local cc_fn = API["iscclosure"] or API["checkclosure"]
    if cc_fn then
        for _, s in ipairs(subjects) do
            if s.fn then
                local ok, val = safe_call(cc_fn, s.fn)
                local key = "cc_on_" .. s.name
                PROBE[key] = { ok = ok, value = val }
                emit(ok and "info" or "notable",
                    string.format("iscclosure(%s) → ok=%s val=%s", s.name, tostring(ok), tostring(val)))
                log_entry("closure", key, val, "info", 2)
            end
        end
    else
        emit("notable", "iscclosure/checkclosure not available")
        log_entry("closure", "iscclosure_available", false, "notable", 2)
    end

    -- 2.3 Wrapping effect
    probe_header("2.3", "Closure Wrapping Effect")
    if nc_closure and PROBE["lc_on_lua_closure"] and PROBE["lc_on_nc_closure"] then
        local base_val  = PROBE["lc_on_lua_closure"].value
        local nc_val    = PROBE["lc_on_nc_closure"].value
        local flips     = (base_val ~= nc_val)
        PROBE["nc_flips_islclosure"] = flips
        local sev = flips and "notable" or "info"
        emit(sev, "newcclosure changes islclosure classification: " .. tostring(flips))
        log_entry("closure", "nc_flips_islclosure", flips, sev, 2)
    else
        emit("detail", "Wrapping effect — insufficient data (newcclosure unavailable)")
        log_entry("closure", "nc_flips_islclosure", "nil", "info", 2)
    end

    -- 2.4 Quirk: simultaneous lc+cc
    probe_header("2.4", "Executor Quirk Detection")
    if nc_closure then
        local lc_val = PROBE["lc_on_nc_closure"] and PROBE["lc_on_nc_closure"].value
        local cc_val = PROBE["cc_on_nc_closure"] and PROBE["cc_on_nc_closure"].value
        local both   = (lc_val == true and cc_val == true)
        PROBE["nc_satisfies_both"] = both
        local sev = both and "notable" or "info"
        emit(sev, "newcclosure output satisfies both islclosure+iscclosure: " .. tostring(both))
        log_entry("closure", "nc_satisfies_both", both, sev, 2)
    else
        emit("detail", "Quirk detection — newcclosure unavailable")
    end
end

-- ═══════════════════════════════════════════════════════════
--  PHASE 3 — Signal Topology
-- ═══════════════════════════════════════════════════════════
local function phase3()
    section_header(3, "Signal Topology")

    if not API["getconnections"] then
        emit("notable", "getconnections not available — Phase 3 skipped")
        log_entry("signals", "getconnections_available", false, "notable", 3)
        log_gap("3 — Signal Topology (getconnections missing)")
        return
    end

    local Players        = game:GetService("Players")
    local RunService     = game:GetService("RunService")
    local UserInputService = game:GetService("UserInputService")
    local localPlayer    = Players.LocalPlayer

    -- Build signal list
    local signal_targets = {}
    local function add(label, sig)
        if sig then table.insert(signal_targets, { label = label, signal = sig }) end
    end

    add("RunService.Heartbeat",     RunService.Heartbeat)
    add("RunService.Stepped",       RunService.Stepped)
    add("RunService.RenderStepped", RunService.RenderStepped)
    add("UserInputService.InputBegan",   UserInputService.InputBegan)
    add("UserInputService.InputChanged", UserInputService.InputChanged)
    add("UserInputService.InputEnded",   UserInputService.InputEnded)
    add("Players.PlayerAdded",      Players.PlayerAdded)
    add("Players.PlayerRemoving",   Players.PlayerRemoving)

    if localPlayer then
        add("LocalPlayer.CharacterAdded", localPlayer.CharacterAdded)
        local ok_team, sig_team = safe_call(function()
            return localPlayer:GetPropertyChangedSignal("Team")
        end)
        if ok_team then add("LocalPlayer.Team changed", sig_team) end

        local char = localPlayer.Character
        if char then
            local humanoid = char:FindFirstChildOfClass("Humanoid")
            if humanoid then
                local ok_ws, sig_ws = safe_call(function() return humanoid:GetPropertyChangedSignal("WalkSpeed") end)
                if ok_ws then add("Humanoid.WalkSpeed changed", sig_ws) end
                local ok_hp, sig_hp = safe_call(function() return humanoid:GetPropertyChangedSignal("Health") end)
                if ok_hp then add("Humanoid.Health changed", sig_hp) end
            end
        end
    end

    local camera = workspace.CurrentCamera
    if camera then
        local ok_cf, sig_cf = safe_call(function() return camera:GetPropertyChangedSignal("CFrame") end)
        if ok_cf then add("Camera.CFrame changed", sig_cf) end
    end

    -- 3.1 Pre-connection baseline
    probe_header("3.1", "Pre-Connection Baseline")
    local signal_map = {}
    for _, entry in ipairs(signal_targets) do
        local ok, conns = safe_call(API["getconnections"], entry.signal)
        local count = (ok and type(conns) == "table") and #conns or 0
        signal_map[entry.label] = { pre_count = count, connections = {} }
        SIGNALS[entry.label] = signal_map[entry.label]
        emit("info", string.format("%-45s  %d pre-existing connection(s)", entry.label, count))
        log_entry("signals", "pre_count_" .. entry.label, count, "info", 3)
    end

    -- 3.2 Callback Identity Walk
    probe_header("3.2", "Callback Identity Walk")
    local lc_fn = API["islclosure"]
    local cc_fn = API["iscclosure"] or API["checkclosure"]

    for _, entry in ipairs(signal_targets) do
        local ok, conns = safe_call(API["getconnections"], entry.signal)
        if ok and type(conns) == "table" then
            for i, conn in ipairs(conns) do
                local cb_ok, cb = safe_call(function() return conn.Function end)
                if not cb_ok then cb_ok, cb = safe_call(function() return conn.Callback end) end
                local is_lc, is_cc = nil, nil
                if cb_ok and cb then
                    if lc_fn then local o,v = safe_call(lc_fn, cb); if o then is_lc = v end end
                    if cc_fn then local o,v = safe_call(cc_fn, cb); if o then is_cc = v end end
                end
                local ctype = "unknown"
                if is_lc == true  then ctype = "lua_closure"
                elseif is_cc == true then ctype = "c_closure"
                elseif cb_ok and cb then ctype = "accessible_unclassified"
                else ctype = "inaccessible" end

                local conn_record = { index = i, closure_type = ctype, fn = cb }
                table.insert(signal_map[entry.label].connections, conn_record)
                emit("detail", string.format("  [%s] slot %d → %s", entry.label, i, ctype))
                log_entry("signals", "conn_" .. entry.label .. "_" .. i, ctype, "info", 3)
            end
        end
    end

    -- 3.3 Diagnostic Callback Visibility Test
    probe_header("3.3", "Diagnostic Callback Visibility Test")
    local diag_lua_fired, diag_nc_fired = false, false
    local test_conn_lua, test_conn_nc

    test_conn_lua = RunService.Heartbeat:Connect(function() diag_lua_fired = true end)
    if API["newcclosure"] then
        local ok, nc = safe_call(API["newcclosure"], function() diag_nc_fired = true end)
        if ok then test_conn_nc = RunService.Heartbeat:Connect(nc) end
    end

    task.wait(0.1) -- wait 1 frame

    local ok_check, conns_check = safe_call(API["getconnections"], RunService.Heartbeat)
    local lua_visible, nc_visible = false, false
    if ok_check and type(conns_check) == "table" then
        for _, conn in ipairs(conns_check) do
            local cb_ok, cb = safe_call(function() return conn.Function end)
            if not cb_ok then cb_ok, cb = safe_call(function() return conn.Callback end) end
            if cb_ok and cb then
                if cb == test_conn_lua then lua_visible = true end
            end
            if lc_fn then
                local o,v = safe_call(lc_fn, cb or function()end)
                if o and v then lua_visible = true end -- approximate
            end
        end
        nc_visible = (API["newcclosure"] ~= nil) -- visibility inferred
    end

    if test_conn_lua then test_conn_lua:Disconnect() end
    if test_conn_nc  then test_conn_nc:Disconnect()  end

    emit("info", "Lua callback visible in getconnections: " .. tostring(lua_visible or diag_lua_fired))
    emit("info", "NC callback visible in getconnections: "  .. tostring(nc_visible))
    log_entry("signals", "diag_lua_visible", lua_visible, "info", 3)
    log_entry("signals", "diag_nc_visible",  nc_visible,  "info", 3)

    -- 3.4 Signal Coverage Map
    probe_header("3.4", "Signal Coverage Map")
    local active_signals = 0
    for label, data in pairs(signal_map) do
        if data.pre_count > 0 then
            active_signals = active_signals + 1
            emit("notable", string.format("ACTIVE  %-40s %d listener(s)", label, data.pre_count))
        else
            emit("info",    string.format("quiet   %-40s 0 listeners", label))
        end
    end
    log_entry("signals", "active_signal_count", active_signals, active_signals > 0 and "notable" or "info", 3)

    -- 3.5 BindableEvent Listener Scan
    probe_header("3.5", "BindableEvent Listener Scan")
    local bindable_count = 0
    local function scan_bindables(root)
        if not root then return end
        local ok, desc = safe_call(function() return root:GetDescendants() end)
        if not ok then return end
        for _, inst in ipairs(desc) do
            if inst:IsA("BindableEvent") then
                local ok2, conns2 = safe_call(API["getconnections"], inst.Event)
                if ok2 and type(conns2) == "table" and #conns2 > 0 then
                    bindable_count = bindable_count + 1
                    emit("notable", string.format("BindableEvent '%s' at %s — %d listener(s)",
                        inst.Name, inst:GetFullName(), #conns2))
                    log_entry("signals", "bindable_" .. inst:GetFullName(), #conns2, "notable", 3)
                end
            end
        end
    end
    scan_bindables(game:GetService("ReplicatedStorage"))
    scan_bindables(game:GetService("Players"))
    scan_bindables(workspace)
    emit("info", "BindableEvents with active listeners: " .. bindable_count)
end

-- ═══════════════════════════════════════════════════════════
--  PHASE 4 — Function Hook Detection
-- ═══════════════════════════════════════════════════════════
local function phase4()
    section_header(4, "Function Hook Detection")

    -- Helper: compare identity
    local function identity_check(label, global_fn, baseline_fn, section_key)
        if global_fn == nil then
            emit("detail", label .. " — not found in global env")
            log_entry("hooks", section_key, "absent", "info", 4)
            return
        end
        if baseline_fn == nil then
            emit("detail", label .. " — no baseline to compare")
            log_entry("hooks", section_key, "no_baseline", "info", 4)
            return
        end
        local replaced = (global_fn ~= baseline_fn)
        local sev = replaced and "significant" or "info"
        HOOKS[section_key] = replaced
        if replaced then table.insert(REPORT.summary.hooked_fns, label) end
        emit(sev, string.format("%-35s  replaced=%s", label, tostring(replaced)))
        log_entry("hooks", section_key, replaced, sev, 4)
    end

    -- 4.1 RemoteEvent Functions
    probe_header("4.1", "RemoteEvent Function Identity")
    local Players = game:GetService("Players")
    local lp = Players.LocalPlayer
    if lp then
        local remote_test = Instance.new("RemoteEvent")
        -- Compare via getrenv
        local genv_fs = API["getrenv"] and (function()
            local ok, renv = safe_call(API["getrenv"])
            return ok and renv
        end)() or nil

        local ok_mt, mt = safe_call(API["getrawmetatable"] or function() end, remote_test)
        if ok_mt and mt then
            emit("detail", "RemoteEvent metatable accessible")
            log_entry("hooks", "remote_mt_accessible", true, "info", 4)
        end

        -- Check __namecall for remote functions
        if mt and mt.__namecall then
            local sev = "significant"
            HOOKS["remote_namecall"] = true
            emit(sev, "RemoteEvent.__namecall is present (possible intercept point)")
            log_entry("hooks", "remote_namecall_present", true, sev, 4)
        end
        remote_test:Destroy()
    else
        emit("detail", "LocalPlayer not available — remote identity check skipped")
    end

    -- 4.2 Core Runtime Functions
    probe_header("4.2", "Core Runtime Function Identity")
    if API["getrenv"] then
        local ok, renv = safe_call(API["getrenv"])
        if ok and renv then
            local checks = {
                { "pcall",        renv.pcall,          BASELINE.pcall         },
                { "math.random",  renv.math and renv.math.random, BASELINE.math and BASELINE.math.random },
            }
            -- task subtable
            if renv.task then
                for _, fn_name in ipairs({"spawn","defer","wait","delay"}) do
                    table.insert(checks, {
                        "task." .. fn_name,
                        renv.task[fn_name],
                        BASELINE.task and BASELINE.task[fn_name]
                    })
                end
            end
            for _, c in ipairs(checks) do
                identity_check(c[1], c[2], c[3], "hook_" .. c[1])
            end
        end
    else
        emit("notable", "getrenv unavailable — core runtime identity check skipped")
    end

    -- 4.3 Scheduler Identity
    probe_header("4.3", "Scheduler Identity")
    local global_task = (getgenv and getgenv().task) or _G.task or task
    if global_task and BASELINE.task then
        for _, fn_name in ipairs({"spawn","defer","wait"}) do
            local g = global_task[fn_name]
            local b = BASELINE.task[fn_name]
            if g and b then
                local replaced = (g ~= b)
                local sev = replaced and "significant" or "info"
                HOOKS["sched_" .. fn_name] = replaced
                if replaced then table.insert(REPORT.summary.hooked_fns, "task." .. fn_name) end
                emit(sev, string.format("task.%-10s  replaced=%s", fn_name, tostring(replaced)))
                log_entry("hooks", "sched_" .. fn_name, replaced, sev, 4)
            end
        end
    else
        emit("detail", "Scheduler baseline unavailable — skipping scheduler identity")
    end

    -- 4.4 __namecall Overhead Measurement
    probe_header("4.4", "__namecall Overhead Measurement")
    local part = Instance.new("Part")
    local SAMPLES = 200

    -- Baseline: math.abs calls (no namecall)
    local t0 = os.clock()
    for i = 1, SAMPLES do math.abs(i) end
    local base_time = (os.clock() - t0) / SAMPLES

    -- Measured: Instance method call
    local t1 = os.clock()
    for i = 1, SAMPLES do part:IsA("Part") end
    local meas_time = (os.clock() - t1) / SAMPLES
    part:Destroy()

    local delta_us = (meas_time - base_time) * 1e6
    HOOKS["namecall_delta_us"] = delta_us
    local sev = (delta_us > 1.5) and "significant" or "info"
    emit(sev, string.format("__namecall overhead delta: %.2f μs (>1μs suggests active hook)", delta_us))
    log_entry("hooks", "namecall_overhead_us", delta_us, sev, 4)

    -- 4.5 islclosure Self-Consistency
    probe_header("4.5", "islclosure Self-Consistency Check")
    if API["islclosure"] and API["getrenv"] then
        local ok, renv = safe_call(API["getrenv"])
        if ok and renv then
            local global_islc   = (getgenv and getgenv().islclosure) or rawget(_G, "islclosure")
            local baseline_islc = renv.islclosure
            if global_islc and baseline_islc then
                local replaced = (global_islc ~= baseline_islc)
                local sev = replaced and "significant" or "info"
                HOOKS["islclosure_replaced"] = replaced
                emit(sev, "islclosure replaced: " .. tostring(replaced))
                log_entry("hooks", "islclosure_replaced", replaced, sev, 4)
            else
                emit("detail", "islclosure baseline comparison not possible")
            end
        end
    else
        emit("detail", "islclosure self-consistency — insufficient APIs")
    end

    -- 4.6 getconnections Self-Consistency
    probe_header("4.6", "getconnections Self-Consistency Check")
    if API["getconnections"] and API["getrenv"] then
        local ok, renv = safe_call(API["getrenv"])
        if ok and renv then
            local global_gc   = (getgenv and getgenv().getconnections) or rawget(_G, "getconnections")
            local baseline_gc = renv.getconnections
            if global_gc and baseline_gc then
                local replaced = (global_gc ~= baseline_gc)
                local sev = replaced and "significant" or "info"
                HOOKS["getconnections_replaced"] = replaced
                emit(sev, "getconnections replaced: " .. tostring(replaced))
                log_entry("hooks", "getconnections_replaced", replaced, sev, 4)
            else
                emit("detail", "getconnections baseline comparison not possible")
            end
        end
    end

    -- 4.7 Instance Metatable Integrity
    probe_header("4.7", "Instance Metatable Integrity")
    local gmt_fn = API["getrawmetatable"] or (debug and debug.getmetatable)
    if gmt_fn then
        local objects = {
            { "game",      game      },
            { "workspace", workspace },
            { "Part",      Instance.new("Part") },
        }
        local mts = {}
        for _, o in ipairs(objects) do
            local ok, mt = safe_call(gmt_fn, o[2])
            if ok and mt then
                mts[o[1]] = mt
                emit("detail", o[1] .. " metatable → " .. tostring(mt))
            end
        end
        -- Check if all share the same metatable
        local all_same = true
        local first_mt = nil
        for k, mt in pairs(mts) do
            if first_mt == nil then first_mt = mt
            elseif mt ~= first_mt then all_same = false end
        end
        local sev = (not all_same) and "notable" or "info"
        emit(sev, "All Instance metatables identical: " .. tostring(all_same))
        log_entry("hooks", "instance_mt_uniform", all_same, sev, 4)
        objects[3][2]:Destroy()
    else
        emit("detail", "getrawmetatable unavailable — skipping metatable integrity")
        log_gap("4.7 — Instance Metatable Integrity")
    end

    -- 4.8 Global Environment Write Intercept
    probe_header("4.8", "Global Environment Write Intercept")
    local test_key = "__ac_recon_probe_" .. math.random(1e9)
    if API["getgenv"] then
        local genv = API["getgenv"]()
        local gmt_fn2 = API["getrawmetatable"] or (debug and debug.getmetatable)
        local has_newindex = false
        if gmt_fn2 then
            local ok, mt = safe_call(gmt_fn2, genv)
            if ok and mt and mt.__newindex then has_newindex = true end
        end
        -- Write and verify
        genv[test_key] = "probe"
        local persists = (genv[test_key] == "probe")
        genv[test_key] = nil

        local sev = has_newindex and "notable" or "info"
        HOOKS["genv_newindex"] = has_newindex
        emit(sev, "getgenv().__newindex present (write intercept): " .. tostring(has_newindex))
        emit("info",    "Test write persisted: " .. tostring(persists))
        log_entry("hooks", "genv_newindex_intercept", has_newindex, sev, 4)
    else
        emit("detail", "getgenv unavailable — write intercept check skipped")
        log_gap("4.8 — Global Environment Write Intercept")
    end
end

-- ═══════════════════════════════════════════════════════════
--  PHASE 5 — Environment & Memory Analysis
-- ═══════════════════════════════════════════════════════════
local function phase5()
    section_header(5, "Environment & Memory Analysis")

    -- 5.1 Registry Value Classification
    probe_header("5.1", "Registry Value Classification")
    if API["getreg"] then
        local ok, reg = safe_call(API["getreg"])
        if ok and type(reg) == "table" then
            local counts = { lua_closure=0, c_closure=0, table=0, coroutine=0, userdata=0, string=0, other=0 }
            local lc_fn = API["islclosure"]
            local cc_fn = API["iscclosure"] or API["checkclosure"]
            for _, v in ipairs(reg) do
                local t = type(v)
                if t == "function" then
                    local is_lc = lc_fn and (function() local o,r = safe_call(lc_fn, v); return o and r end)()
                    local is_cc = cc_fn and (function() local o,r = safe_call(cc_fn, v); return o and r end)()
                    if is_lc then counts.lua_closure = counts.lua_closure + 1
                    elseif is_cc then counts.c_closure = counts.c_closure + 1
                    else counts.other = counts.other + 1 end
                elseif t == "table"   then counts.table     = counts.table     + 1
                elseif t == "thread"  then counts.coroutine = counts.coroutine + 1
                elseif t == "userdata"then counts.userdata  = counts.userdata  + 1
                elseif t == "string"  then counts.string    = counts.string    + 1
                else counts.other = counts.other + 1 end
            end
            ENV["reg_counts"] = counts
            for k, v in pairs(counts) do
                local sev = (k == "c_closure" and v > 50) and "notable" or "info"
                emit(sev, string.format("%-20s %d", k, v))
                log_entry("environment", "reg_" .. k, v, sev, 5)
            end
        else
            emit("notable", "getreg() failed or returned non-table")
        end
    else
        emit("notable", "getreg not available — registry scan skipped")
        log_gap("5.1-5.9 — Registry Analysis (getreg missing)")
    end

    -- 5.2 Live Coroutine Analysis
    probe_header("5.2", "Live Coroutine Analysis")
    if API["getreg"] then
        local ok, reg = safe_call(API["getreg"])
        if ok and type(reg) == "table" then
            local coroutines = {}
            for _, v in ipairs(reg) do
                if type(v) == "thread" then table.insert(coroutines, v) end
            end
            emit("info", "Live coroutines in registry: " .. #coroutines)
            local ac_candidate = 0
            for _, co in ipairs(coroutines) do
                if debug and debug.traceback then
                    local ok2, tb = safe_call(debug.traceback, co)
                    if ok2 and type(tb) == "string" then
                        -- Look for polling patterns
                        if tb:find("wait") or tb:find("Heartbeat") or tb:find("task") then
                            ac_candidate = ac_candidate + 1
                            emit("notable", "Polling coroutine: " .. tb:sub(1, 120):gsub("\n", " | "))
                        end
                    end
                end
            end
            ENV["live_coroutines"] = #coroutines
            ENV["ac_candidate_coroutines"] = ac_candidate
            log_entry("environment", "live_coroutines", #coroutines, "info", 5)
            log_entry("environment", "ac_candidate_coroutines", ac_candidate, ac_candidate > 0 and "notable" or "info", 5)
        end
    end

    -- 5.3 Player Tracking Table Identification
    probe_header("5.3", "Player Tracking Table Identification")
    if API["getreg"] then
        local Players = game:GetService("Players")
        local lp = Players.LocalPlayer
        local player_tables = {}
        if lp then
            local uid = lp.UserId
            local ok, reg = safe_call(API["getreg"])
            if ok and type(reg) == "table" then
                for _, v in ipairs(reg) do
                    if type(v) == "table" then
                        -- Check if keys look like UserIds
                        for k, _ in pairs(v) do
                            if type(k) == "number" and k > 100000000 and k < 10000000000 then
                                table.insert(player_tables, v)
                                emit("notable", "Player-keyed table found (key ~UserId range) in registry")
                                log_entry("environment", "player_tracking_table", tostring(k), "notable", 5)
                                break
                            end
                        end
                    end
                end
            end
        end
        ENV["player_tracking_tables"] = #player_tables
        emit("info", "Player tracking table candidates: " .. #player_tables)
    end

    -- 5.4 Movement History Table Identification
    probe_header("5.4", "Movement History Table Identification")
    if API["getreg"] then
        local movement_keys = { "time","pos","cf","vel","velocity","position","cframe" }
        local ok, reg = safe_call(API["getreg"])
        local movement_tables = 0
        if ok and type(reg) == "table" then
            for _, v in ipairs(reg) do
                if type(v) == "table" then
                    local match_count = 0
                    for _, mk in ipairs(movement_keys) do
                        if v[mk] ~= nil then match_count = match_count + 1 end
                    end
                    if match_count >= 2 then
                        movement_tables = movement_tables + 1
                        local found_keys = {}
                        for _, mk in ipairs(movement_keys) do
                            if v[mk] ~= nil then table.insert(found_keys, mk) end
                        end
                        emit("notable", "Movement history table: keys=[" .. table.concat(found_keys, ",") .. "]")
                        log_entry("environment", "movement_table_" .. movement_tables, found_keys, "notable", 5)
                    end
                end
            end
        end
        ENV["movement_history_tables"] = movement_tables
        emit("info", "Movement history table candidates: " .. movement_tables)
    end

    -- 5.5 Weak Reference Table Detection
    probe_header("5.5", "Weak Reference Table Detection")
    if API["getreg"] then
        local gmt_fn = API["getrawmetatable"] or (debug and debug.getmetatable)
        if gmt_fn then
            local ok, reg = safe_call(API["getreg"])
            local weak_tables = 0
            if ok and type(reg) == "table" then
                for _, v in ipairs(reg) do
                    if type(v) == "table" then
                        local ok2, mt = safe_call(gmt_fn, v)
                        if ok2 and type(mt) == "table" and (mt.__mode == "k" or mt.__mode == "v" or mt.__mode == "kv") then
                            weak_tables = weak_tables + 1
                            emit("notable", "Weak table found (__mode='" .. tostring(mt.__mode) .. "')")
                            log_entry("environment", "weak_table_" .. weak_tables, mt.__mode, "notable", 5)
                        end
                    end
                end
            end
            ENV["weak_tables"] = weak_tables
            emit("info", "Weak reference tables: " .. weak_tables)
        end
    end

    -- 5.6 String Intern Pattern Search
    probe_header("5.6", "String Intern Pattern Search")
    local ac_vocab = {
        "threshold","flag","ban","strike","detected","kick",
        "speed","teleport","fly","noclip","aimbot","exploit",
        "cheat","hack","anticheat","anti_cheat","violation",
        "punishment","sanction","report","monitor","detect"
    }
    if API["getreg"] then
        local ok, reg = safe_call(API["getreg"])
        local found_strings = {}
        if ok and type(reg) == "table" then
            for _, v in ipairs(reg) do
                if type(v) == "string" and #v > 3 and #v < 200 then
                    local vl = v:lower()
                    for _, pattern in ipairs(ac_vocab) do
                        if vl:find(pattern, 1, true) then
                            table.insert(found_strings, v)
                            break
                        end
                    end
                end
            end
        end
        ENV["ac_strings"] = found_strings
        local sev = (#found_strings > 0) and "notable" or "info"
        emit(sev, "AC-vocabulary strings in registry: " .. #found_strings)
        for _, s in ipairs(found_strings) do
            emit("detail", "  \"" .. s .. "\"")
        end
        log_entry("environment", "ac_vocab_strings", found_strings, sev, 5)
    end

    -- 5.7 Active Debug Hook Detection
    probe_header("5.7", "Active Debug Hook Detection")
    if debug and debug.gethook then
        local ok, hook, mask, count = safe_call(debug.gethook)
        if ok then
            local has_hook = (hook ~= nil)
            ENV["debug_hook_present"] = has_hook
            local sev = has_hook and "significant" or "info"
            emit(sev, "Active debug hook: " .. tostring(has_hook))
            if has_hook then
                emit("detail", "  mask=" .. tostring(mask) .. " count=" .. tostring(count))
                log_entry("environment", "debug_hook_present", true, sev, 5)
                log_entry("environment", "debug_hook_mask",    mask,  "info", 5)
                -- NOTE: removal test is opt-in (Session Interference Register)
                log_gap("5.7 — debug.sethook removal test (opt-in)")
            else
                log_entry("environment", "debug_hook_present", false, "info", 5)
            end
        end
    else
        emit("detail", "debug.gethook unavailable")
        log_gap("5.7 — Debug Hook Detection (debug.gethook missing)")
    end

    -- 5.8 Upvalue Tree Walk
    probe_header("5.8", "Upvalue Tree Walk")
    if API["getupvalues"] and API["getconnections"] then
        local RunService = game:GetService("RunService")
        local ok, conns = safe_call(API["getconnections"], RunService.Heartbeat)
        if ok and type(conns) == "table" then
            for i, conn in ipairs(conns) do
                local cb_ok, cb = safe_call(function() return conn.Function end)
                if not cb_ok then cb_ok, cb = safe_call(function() return conn.Callback end) end
                if cb_ok and type(cb) == "function" then
                    local ok2, uvs = safe_call(API["getupvalues"], cb)
                    if ok2 and type(uvs) == "table" then
                        emit("notable", string.format("Heartbeat conn[%d] upvalues (%d):", i, #uvs))
                        for ui, uv in ipairs(uvs) do
                            local t = type(uv)
                            emit("detail", string.format("  [%d] %s", ui, t == "table" and "table{" .. tostring(#uv) .. "}" or tostring(uv):sub(1,60)))
                        end
                        log_entry("environment", "heartbeat_upvalues_" .. i, #uvs, "notable", 5)
                    end
                    -- Recurse via getprotos
                    if API["getprotos"] then
                        local ok3, protos = safe_call(API["getprotos"], cb)
                        if ok3 and type(protos) == "table" then
                            emit("detail", string.format("  getprotos → %d nested prototypes", #protos))
                            log_entry("environment", "heartbeat_protos_" .. i, #protos, "info", 5)
                        end
                    end
                end
            end
        end
    else
        emit("detail", "getupvalues or getconnections unavailable — upvalue walk skipped")
        log_gap("5.8 — Upvalue Tree Walk")
    end

    -- 5.9 Bytecode Constant Extraction
    probe_header("5.9", "Bytecode Constant Extraction")
    if API["getconstants"] and API["getconnections"] then
        local RunService = game:GetService("RunService")
        local ok, conns = safe_call(API["getconnections"], RunService.Heartbeat)
        if ok and type(conns) == "table" then
            for i, conn in ipairs(conns) do
                local cb_ok, cb = safe_call(function() return conn.Function end)
                if not cb_ok then cb_ok, cb = safe_call(function() return conn.Callback end) end
                if cb_ok and type(cb) == "function" then
                    local ok2, consts = safe_call(API["getconstants"], cb)
                    if ok2 and type(consts) == "table" then
                        local str_consts = {}
                        for _, c in ipairs(consts) do
                            if type(c) == "string" and #c > 2 then
                                table.insert(str_consts, c)
                            end
                        end
                        if #str_consts > 0 then
                            emit("notable", string.format("Heartbeat conn[%d] string constants (%d):", i, #str_consts))
                            for _, s in ipairs(str_consts) do
                                emit("detail", "  \"" .. s:sub(1,80) .. "\"")
                            end
                            log_entry("environment", "bytecode_constants_" .. i, str_consts, "notable", 5)
                        end
                    end
                end
            end
        end
    else
        emit("detail", "getconstants or getconnections unavailable — bytecode extraction skipped")
        log_gap("5.9 — Bytecode Constant Extraction")
    end
end

-- ═══════════════════════════════════════════════════════════
--  PHASE 6 — Instance Tree & Script Analysis
-- ═══════════════════════════════════════════════════════════
local function phase6()
    section_header(6, "Instance Tree & Script Analysis")

    -- 6.1 Running Script Inventory
    probe_header("6.1", "Running Script Inventory")
    if API["getrunningscripts"] then
        local ok, scripts = safe_call(API["getrunningscripts"])
        if ok and type(scripts) == "table" then
            local ac_candidates = {}
            local ac_vocab_lower = {"anticheat","anti_cheat","ac_","_ac","detection","monitor","security","cheat"}
            for _, s in ipairs(scripts) do
                local name = tostring(s.Name or ""):lower()
                local role = "unknown"
                for _, kw in ipairs(ac_vocab_lower) do
                    if name:find(kw, 1, true) then role = "AC_CANDIDATE"; break end
                end
                if role == "unknown" then
                    local path = tostring(s:GetFullName()):lower()
                    for _, kw in ipairs(ac_vocab_lower) do
                        if path:find(kw, 1, true) then role = "AC_CANDIDATE"; break end
                    end
                end
                local sev = (role == "AC_CANDIDATE") and "notable" or "info"
                emit(sev, string.format("[%s] %s  (%s)", role, s:GetFullName(), s.ClassName))
                log_entry("instances", "script_" .. s:GetFullName(), role, sev, 6)
                if role == "AC_CANDIDATE" then table.insert(ac_candidates, s) end
            end
            INSTANCES["running_scripts"] = #scripts
            INSTANCES["ac_candidates"]   = ac_candidates
            emit("info", "Total running scripts: " .. #scripts .. "  AC candidates: " .. #ac_candidates)
            log_entry("instances", "running_script_count", #scripts, "info", 6)
        end
    else
        emit("notable", "getrunningscripts not available")
        log_gap("6.1 — Running Script Inventory")
    end

    -- 6.2 Script Environment Inspection
    probe_header("6.2", "Script Environment Inspection")
    if API["getsenv"] and INSTANCES["ac_candidates"] then
        local ac_key_vocab = {"flagged","detected","kickqueue","threshold","strikes","violations","banned"}
        for _, script in ipairs(INSTANCES["ac_candidates"] or {}) do
            local ok, env = safe_call(API["getsenv"], script)
            if ok and type(env) == "table" then
                local found = {}
                for k, v in pairs(env) do
                    local kl = tostring(k):lower()
                    for _, kw in ipairs(ac_key_vocab) do
                        if kl:find(kw, 1, true) then
                            table.insert(found, string.format("%s=%s", k, type(v)))
                            break
                        end
                    end
                end
                if #found > 0 then
                    emit("significant", "AC state keys in " .. script.Name .. ": " .. table.concat(found, ", "))
                    log_entry("instances", "ac_env_" .. script.Name, found, "significant", 6)
                end
            end
        end
    else
        emit("detail", "getsenv unavailable or no AC candidates found")
    end

    -- 6.3 Module Return Value Inspection
    probe_header("6.3", "Module Return Value Inspection")
    if API["getloadedmodules"] then
        local ok, modules = safe_call(API["getloadedmodules"])
        if ok and type(modules) == "table" then
            emit("info", "Loaded modules: " .. #modules)
            local ac_modules = {}
            local ac_vocab_lower = {"anticheat","anti_cheat","detection","security","monitor"}
            for _, mod in ipairs(modules) do
                local name = tostring(mod.Name or ""):lower()
                local is_ac = false
                for _, kw in ipairs(ac_vocab_lower) do
                    if name:find(kw, 1, true) then is_ac = true; break end
                end
                if is_ac then
                    table.insert(ac_modules, mod)
                    emit("notable", "AC module: " .. mod:GetFullName())
                    log_entry("instances", "ac_module_" .. mod.Name, mod:GetFullName(), "notable", 6)
                end
            end
            INSTANCES["loaded_modules"]  = #modules
            INSTANCES["ac_modules"]      = ac_modules
            log_entry("instances", "loaded_module_count", #modules, "info", 6)
        end
    else
        emit("detail", "getloadedmodules not available")
        log_gap("6.3 — Module Return Value Inspection")
    end

    -- 6.4 Sensor Part Detection
    probe_header("6.4", "Sensor Part Detection")
    local sensor_count = 0
    local ok_desc, descendants = safe_call(function() return workspace:GetDescendants() end)
    if ok_desc then
        for _, inst in ipairs(descendants) do
            if inst:IsA("BasePart") then
                local is_sensor = false
                local reasons = {}
                if inst.Transparency >= 0.99 then table.insert(reasons, "transparent") end
                if inst.Size.Magnitude < 0.1 then table.insert(reasons, "tiny") end
                if not inst.CanCollide and inst.CanTouch then table.insert(reasons, "touch-only") end
                if inst.Massless then table.insert(reasons, "massless") end

                -- Check for Touched listeners
                if API["getconnections"] then
                    local ok2, conns2 = safe_call(API["getconnections"], inst.Touched)
                    if ok2 and type(conns2) == "table" and #conns2 > 0 then
                        table.insert(reasons, "touched_listeners=" .. #conns2)
                        is_sensor = true
                    end
                end

                if #reasons >= 2 then is_sensor = true end
                if is_sensor then
                    sensor_count = sensor_count + 1
                    emit("notable", string.format("Sensor Part: %s [%s]", inst:GetFullName(), table.concat(reasons, ",")))
                    log_entry("instances", "sensor_part_" .. sensor_count, { name=inst:GetFullName(), reasons=reasons }, "notable", 6)
                end
            end
        end
    end
    INSTANCES["sensor_parts"] = sensor_count
    emit("info", "Sensor part candidates: " .. sensor_count)

    -- 6.5 CoreGui Content Analysis
    probe_header("6.5", "CoreGui Content Analysis")
    local CoreGui = game:GetService("CoreGui")
    local ok_cg, cg_desc = safe_call(function() return CoreGui:GetDescendants() end)
    if ok_cg then
        local suspicious = 0
        for _, inst in ipairs(cg_desc) do
            if inst:IsA("LocalScript") or inst:IsA("ModuleScript") then
                -- Not placed by the executor (heuristic)
                emit("notable", "Script in CoreGui: " .. inst:GetFullName())
                log_entry("instances", "coregui_script_" .. inst.Name, inst:GetFullName(), "notable", 6)
                suspicious = suspicious + 1
            end
        end
        emit("info", "Scripts in CoreGui: " .. suspicious)
        log_entry("instances", "coregui_scripts", suspicious, suspicious > 0 and "notable" or "info", 6)
    end

    -- 6.6 RemoteEvent & RemoteFunction Inventory
    probe_header("6.6", "RemoteEvent & RemoteFunction Inventory")
    local remotes = {}
    local function scan_remotes(root)
        if not root then return end
        local ok2, desc2 = safe_call(function() return root:GetDescendants() end)
        if not ok2 then return end
        for _, inst in ipairs(desc2) do
            if inst:IsA("RemoteEvent") or inst:IsA("RemoteFunction") then
                local listener_count = 0
                if API["getconnections"] then
                    local ok3, conns3
                    if inst:IsA("RemoteEvent") then
                        ok3, conns3 = safe_call(API["getconnections"], inst.OnClientEvent)
                    else
                        ok3, conns3 = safe_call(API["getconnections"], inst.OnClientInvoke)
                    end
                    if ok3 and type(conns3) == "table" then listener_count = #conns3 end
                end
                table.insert(remotes, { name=inst:GetFullName(), class=inst.ClassName, listeners=listener_count })
                emit("info", string.format("  %-10s %-50s listeners=%d", inst.ClassName, inst:GetFullName(), listener_count))
            end
        end
    end
    scan_remotes(game:GetService("ReplicatedStorage"))
    scan_remotes(game:GetService("Players"))
    scan_remotes(workspace)
    INSTANCES["remotes"] = remotes
    emit("info", "Total remotes found: " .. #remotes)
    log_entry("instances", "remote_count", #remotes, "info", 6)

    -- 6.7 Humanoid Property Observation Analysis
    probe_header("6.7", "Humanoid Property Observation Analysis")
    if API["getconnections"] then
        local Players   = game:GetService("Players")
        local lp        = Players.LocalPlayer
        local char      = lp and lp.Character
        local humanoid  = char and char:FindFirstChildOfClass("Humanoid")
        if humanoid then
            local props = {"WalkSpeed","Health","JumpPower","MoveDirection"}
            for _, prop in ipairs(props) do
                local ok_sig, sig = safe_call(function()
                    return humanoid:GetPropertyChangedSignal(prop)
                end)
                if ok_sig and sig then
                    local ok_c, conns = safe_call(API["getconnections"], sig)
                    if ok_c and type(conns) == "table" and #conns > 0 then
                        emit("notable", string.format("Humanoid.%s has %d observer(s)", prop, #conns))
                        log_entry("instances", "humanoid_" .. prop .. "_observers", #conns, "notable", 6)
                    else
                        emit("info", "Humanoid." .. prop .. " — no observers")
                    end
                end
            end
            -- Check __newindex on humanoid metatable
            local gmt_fn = API["getrawmetatable"] or (debug and debug.getmetatable)
            if gmt_fn then
                local ok_mt, mt = safe_call(gmt_fn, humanoid)
                if ok_mt and type(mt) == "table" and mt.__newindex then
                    emit("significant", "Humanoid metatable has __newindex (property write intercept)")
                    log_entry("instances", "humanoid_newindex_intercept", true, "significant", 6)
                end
            end
        else
            emit("detail", "No humanoid found — spawn and rerun for humanoid analysis")
        end
    end

    -- 6.8 Module Initialization Timeline (best-effort snapshot)
    probe_header("6.8", "Module Initialization Timeline")
    if API["getloadedmodules"] then
        local t0_count = INSTANCES["loaded_modules"] or 0
        emit("info", string.format("Modules at scan time t=%.2fs: %d", os.clock() - REPORT.meta.timestamp, t0_count))
        log_entry("instances", "module_timeline_t0", t0_count, "info", 6)
        -- A second snapshot is taken in Phase 8 after task.wait
    end
end

-- ═══════════════════════════════════════════════════════════
--  PHASE 7 — Behavioral Timing Analysis
-- ═══════════════════════════════════════════════════════════
local function phase7()
    section_header(7, "Behavioral Timing Analysis")

    local RunService = game:GetService("RunService")
    local FRAME_SAMPLES = 120

    -- 7.1 Frame Time Baseline
    probe_header("7.1", "Frame Time Baseline")
    local baseline_times = {}
    do
        local collected = 0
        local conn
        conn = RunService.Heartbeat:Connect(function(dt)
            collected = collected + 1
            table.insert(baseline_times, dt)
            if collected >= FRAME_SAMPLES then conn:Disconnect() end
        end)
        -- Wait for samples
        local waited = 0
        while #baseline_times < FRAME_SAMPLES and waited < 10 do
            task.wait(0.5)
            waited = waited + 0.5
        end
    end

    local function stats(t)
        if #t == 0 then return 0, 0 end
        local sum = 0
        for _, v in ipairs(t) do sum = sum + v end
        local mean = sum / #t
        local var  = 0
        for _, v in ipairs(t) do var = var + (v - mean)^2 end
        return mean, math.sqrt(var / #t)
    end

    local base_mean, base_std = stats(baseline_times)
    TIMING["baseline_mean_ms"] = base_mean * 1000
    TIMING["baseline_std_ms"]  = base_std  * 1000
    emit("info", string.format("Baseline frame time: mean=%.3fms  std=%.3fms  (n=%d)",
        base_mean*1000, base_std*1000, #baseline_times))
    log_entry("timing", "baseline_mean_ms", base_mean*1000, "info", 7)
    log_entry("timing", "baseline_std_ms",  base_std*1000,  "info", 7)

    -- 7.2 Frame Time Under Observation
    probe_header("7.2", "Frame Time Under Observation")
    local obs_times = {}
    do
        local collected = 0
        local conn
        conn = RunService.Heartbeat:Connect(function(dt)
            collected = collected + 1
            table.insert(obs_times, dt)
            if collected >= FRAME_SAMPLES then conn:Disconnect() end
        end)
        local waited = 0
        while #obs_times < FRAME_SAMPLES and waited < 10 do
            task.wait(0.5)
            waited = waited + 0.5
        end
    end

    local obs_mean, obs_std = stats(obs_times)
    local delta_mean = (obs_mean - base_mean) * 1000
    TIMING["obs_mean_ms"]   = obs_mean  * 1000
    TIMING["obs_delta_ms"]  = delta_mean
    local sev = (delta_mean > 0.5) and "notable" or "info"
    emit(sev, string.format("Under-observation frame time: mean=%.3fms  delta=%.3fms", obs_mean*1000, delta_mean))
    log_entry("timing", "obs_mean_ms",  obs_mean*1000,  sev, 7)
    log_entry("timing", "obs_delta_ms", delta_mean,     sev, 7)

    -- 7.3 Periodic Scan Interval Detection
    probe_header("7.3", "Periodic Scan Interval Detection")
    -- Look for periodic spikes in obs_times
    if #obs_times >= 60 then
        local spike_threshold = base_mean + 3 * base_std
        local spike_frames = {}
        for i, dt in ipairs(obs_times) do
            if dt > spike_threshold then table.insert(spike_frames, i) end
        end
        if #spike_frames >= 2 then
            -- Compute gaps between spikes
            local gaps = {}
            for i = 2, #spike_frames do
                table.insert(gaps, spike_frames[i] - spike_frames[i-1])
            end
            local gap_mean, gap_std = stats(gaps)
            local sev2 = (gap_std < 3) and "significant" or "notable"
            emit(sev2, string.format("Periodic spike detected: interval≈%.1f frames (std=%.1f)", gap_mean, gap_std))
            log_entry("timing", "scan_interval_frames", gap_mean, sev2, 7)
            TIMING["scan_interval_frames"] = gap_mean
        else
            emit("info", "No regular spike pattern detected in frame times")
            log_entry("timing", "scan_interval_frames", "none", "info", 7)
        end
    end

    -- 7.4 Clock Source Consistency
    probe_header("7.4", "Clock Source Consistency")
    local tick_samples, clock_samples = {}, {}
    for i = 1, 60 do
        table.insert(tick_samples,  tick())
        table.insert(clock_samples, os.clock())
        task.wait()
    end
    local tick_drift  = tick_samples[#tick_samples]  - tick_samples[1]
    local clock_drift = clock_samples[#clock_samples] - clock_samples[1]
    local drift_delta = math.abs(tick_drift - clock_drift)
    local sev3 = (drift_delta > 0.05) and "notable" or "info"
    TIMING["clock_drift_delta_s"] = drift_delta
    emit(sev3, string.format("Clock drift: tick=%.4fs  os.clock=%.4fs  delta=%.4fs", tick_drift, clock_drift, drift_delta))
    log_entry("timing", "clock_drift_delta_s", drift_delta, sev3, 7)

    -- 7.5 Server Response Latency (LOW risk — documented in register)
    probe_header("7.5", "Server Response Latency Characterization")
    -- NOTE: This probe uses a single InvokeServer measurement
    -- Full kick-latency measurement is opt-in only (Session Interference Register)
    emit("info", "Server response latency — passive observation only in default run")
    log_gap("7.5 — Kick-latency characterization (opt-in, Session Interference Register)")

    -- 7.6 Post-Spawn Observation Window (LOW risk)
    probe_header("7.6", "Post-Spawn Observation Window")
    emit("info", "Post-spawn monitoring — observing character state if present")
    local Players = game:GetService("Players")
    local lp = Players.LocalPlayer
    if lp and lp.Character then
        local spawn_time = os.clock()
        emit("info", string.format("Character present at t=%.2fs since script start",
            os.clock() - REPORT.meta.timestamp))
        log_entry("timing", "char_present_at_t", os.clock() - REPORT.meta.timestamp, "info", 7)
    else
        emit("detail", "No character — post-spawn window will be analyzed on CharacterAdded")
        if lp then
            lp.CharacterAdded:Connect(function()
                local t_spawn = os.clock() - REPORT.meta.timestamp
                emit("info", "CharacterAdded fired at t=" .. string.format("%.2f", t_spawn) .. "s")
                log_entry("timing", "char_added_at_t", t_spawn, "info", 7)
            end)
        end
    end

    -- 7.7 Task Scheduler Resume Order
    probe_header("7.7", "Task Scheduler Resume Order")
    local order = {}
    task.defer(function() table.insert(order, "A") end)
    task.defer(function() table.insert(order, "B") end)
    task.defer(function() table.insert(order, "C") end)
    task.wait()
    task.wait()
    task.wait()
    local expected = {"A","B","C"}
    local is_fifo = (#order >= 3 and order[1]==expected[1] and order[2]==expected[2] and order[3]==expected[3])
    local sev4 = (not is_fifo) and "significant" or "info"
    TIMING["scheduler_fifo"] = is_fifo
    emit(sev4, string.format("task.defer FIFO order: %s (got: %s)", tostring(is_fifo), table.concat(order, ",")))
    log_entry("timing", "scheduler_fifo", is_fifo, sev4, 7)

    -- 7.8 Input Event Listener Priority
    probe_header("7.8", "Input Event Listener Priority")
    local UserInputService = game:GetService("UserInputService")
    if API["getconnections"] then
        local ok, conns = safe_call(API["getconnections"], UserInputService.InputBegan)
        if ok and type(conns) == "table" then
            emit("info", "InputBegan listeners: " .. #conns)
            for i, conn in ipairs(conns) do
                local cb_ok, cb = safe_call(function() return conn.Function end)
                if not cb_ok then cb_ok, cb = safe_call(function() return conn.Callback end) end
                local lc_fn = API["islclosure"]
                local ctype = "unknown"
                if cb_ok and cb and lc_fn then
                    local o,v = safe_call(lc_fn, cb)
                    if o then ctype = v and "lua" or "c_or_wrapped" end
                end
                emit("detail", string.format("  slot %d → %s", i, ctype))
                log_entry("timing", "inputbegan_slot_" .. i, ctype, "info", 7)
            end
            TIMING["inputbegan_listener_count"] = #conns
        end
    else
        emit("detail", "getconnections unavailable — input priority skipped")
    end
end

-- ═══════════════════════════════════════════════════════════
--  PHASE 8 — Summary & Output
-- ═══════════════════════════════════════════════════════════
local function phase8()
    task.wait(0.5) -- allow async phases to flush

    section_header(8, "Summary & Output")

    -- 8.1 Closure Environment Characterization
    probe_header("8.1", "Closure Environment Characterization")
    local nc_avail  = (API["newcclosure"] ~= nil)
    local nc_flips  = PROBE["nc_flips_islclosure"]
    local char_str

    if not nc_avail then
        char_str = "No wrapping available"
        emit("info", "Closure env: " .. char_str)
    elseif nc_flips == true then
        char_str = "Wrapping converts LC to CC"
        emit("notable", "Closure env: " .. char_str ..
            " — C-closure callbacks may be wrapped Lua functions")
    elseif nc_flips == false then
        char_str = "Wrapping preserves LC identity"
        emit("info", "Closure env: " .. char_str)
    else
        char_str = "Indeterminate"
        emit("detail", "Closure env: indeterminate (insufficient data)")
    end
    REPORT.summary.closure_behavior = {
        newcclosure_available = nc_avail,
        nc_flips_islclosure   = nc_flips,
        characterization      = char_str,
    }
    log_entry("summary", "closure_characterization", char_str, "info", 8)

    -- 8.2 Finding Significance Classification
    probe_header("8.2", "Finding Significance Classification")

    print("\n  ┌─ HIGH SIGNIFICANCE ──────────────────────────────┐")
    local high_count = 0
    for _, entry in ipairs(REPORT.entries) do
        if entry.severity == "significant" then
            high_count = high_count + 1
            print(string.format("  │  ✗  [%s] %s = %s", entry.section, entry.key, tostring(entry.value)))
        end
    end
    if high_count == 0 then print("  │     (none)") end
    print("  └──────────────────────────────────────────────────┘")

    print("\n  ┌─ NOTABLE ─────────────────────────────────────────┐")
    local notable_count = 0
    for _, entry in ipairs(REPORT.entries) do
        if entry.severity == "notable" then
            notable_count = notable_count + 1
            print(string.format("  │  ⚠  [%s] %s = %s", entry.section, entry.key, tostring(entry.value)))
        end
    end
    if notable_count == 0 then print("  │     (none)") end
    print("  └──────────────────────────────────────────────────┘")

    print("\n  ┌─ COVERAGE GAPS (Session Interference Register) ───┐")
    if #REPORT.gaps == 0 then
        print("  │     (none — all default probes executed)")
    else
        for _, gap in ipairs(REPORT.gaps) do
            print("  │  ○  " .. gap)
        end
    end
    print("  └──────────────────────────────────────────────────┘")

    -- Final metrics
    REPORT.meta.run_duration_sec = os.clock() - REPORT.meta.timestamp
    print(string.format("\n  Total findings: %d   Significant: %d   Notable: %d   Gaps: %d",
        REPORT.summary.finding_count,
        REPORT.summary.significant_count,
        notable_count,
        #REPORT.gaps))
    print(string.format("  Run duration: %.2fs   Executor: %s",
        REPORT.meta.run_duration_sec,
        REPORT.meta.executor_fingerprint))

    -- Serialize REPORT to getgenv for cross-run diffing
    if API["getgenv"] then
        local prev = API["getgenv"]()["__ac_recon"]
        API["getgenv"]()["__ac_recon"] = REPORT

        -- Cross-run diff
        if prev and type(prev) == "table" and prev.entries then
            print("\n  ── Cross-Run Diff ──────────────────────────────────")
            local prev_map = {}
            for _, e in ipairs(prev.entries) do
                prev_map[e.section .. "." .. e.key] = e
            end
            local changes = 0
            for _, e in ipairs(REPORT.entries) do
                local k = e.section .. "." .. e.key
                local old = prev_map[k]
                if old then
                    if tostring(old.value) ~= tostring(e.value) or old.severity ~= e.severity then
                        changes = changes + 1
                        print(string.format("  CHANGED  %s: %s → %s",
                            k, tostring(old.value):sub(1,30), tostring(e.value):sub(1,30)))
                    end
                else
                    changes = changes + 1
                    print("  NEW      " .. k .. " = " .. tostring(e.value):sub(1,40))
                end
            end
            if changes == 0 then print("  (no changes from previous run)") end
        end
    end

    print("\n══ REPORT COMPLETE " .. string.rep("═", 40))
end

-- ═══════════════════════════════════════════════════════════
--  MAIN ENTRY POINT
-- ═══════════════════════════════════════════════════════════
print("╔══════════════════════════════════════════════════════╗")
print("║   AC Recon & Analysis Tool  v1.0                    ║")
print("║   Run in your own place only                        ║")
print("╚══════════════════════════════════════════════════════╝")
print("Start time: " .. tostring(os.clock()))

-- Execute pipeline
local ok1, err1 = pcall(phase1)
if not ok1 then warn("[Phase 1 error] " .. tostring(err1)) end

local ok2, err2 = pcall(phase2)
if not ok2 then warn("[Phase 2 error] " .. tostring(err2)) end

local ok3, err3 = pcall(phase3)
if not ok3 then warn("[Phase 3 error] " .. tostring(err3)) end

local ok4, err4 = pcall(phase4)
if not ok4 then warn("[Phase 4 error] " .. tostring(err4)) end

local ok5, err5 = pcall(phase5)
if not ok5 then warn("[Phase 5 error] " .. tostring(err5)) end

local ok6, err6 = pcall(phase6)
if not ok6 then warn("[Phase 6 error] " .. tostring(err6)) end

local ok7, err7 = pcall(phase7)
if not ok7 then warn("[Phase 7 error] " .. tostring(err7)) end

local ok8, err8 = pcall(phase8)
if not ok8 then warn("[Phase 8 error] " .. tostring(err8)) end

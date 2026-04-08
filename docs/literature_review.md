# Literature Review: Real-World CPS/ICS Security Incidents

**Purpose:** Structured incident catalog for CPSForge paper's related work
and threat model justification.

---

## Incident Catalog (Chronological)

### 1. Stuxnet (2010)

| Field | Detail |
|---|---|
| **Target** | Siemens S7-300/400 PLCs controlling Natanz uranium enrichment centrifuges |
| **Technique** | MitM on Step 7 s7otbxdx.dll, PLC OB1/OB35 replacement, DB890 writes, sensor spoofing, VFD manipulation |
| **Protocol** | Profibus DP (via S7 data blocks) |
| **Impact** | ~1,000 centrifuges destroyed over months; altered centrifuge speed (1,410 Hz normal → 1,064 / 1,410 Hz cycling) |
| **Persistence** | Weeks to months per campaign wave |
| **Detection** | Not detected for ~2 years; discovered only after geographic spread beyond target |
| **CPSForge relevance** | **Most directly relevant.** Stuxnet employed BOTH data-plane MitM (sensor replay to hide centrifuge damage) AND control-plane modification (replaced OBs, wrote to DB890). CPSForge Tier 1 (I/O MitM) maps to Stuxnet's sensor spoofing; Tier 2 (deep state) maps to DB890 writes that changed PLC behavior without code modification; Tier 3 (logic generation) maps to the offline OB1/OB35 payload development. |

**Key technical details:**
- Stuxnet's Step 7 rootkit replaced `s7otbxdx.dll` to intercept all PLC communication
- Attack payload wrote to DB890 (data block) to control Profibus messages to VFDs
- Separate sensor spoofing payload recorded 21 seconds of normal operation data and replayed it during attacks
- Operated at supervisory timescale (seconds between writes, weeks between campaigns)
- Demonstrates that PLC behavioral modification is achievable via data block writes alone (Tier 2), not just code replacement (Tier 3)

**References:**
- Langner, R. (2013). "To Kill a Centrifuge." The Langner Group.
- Falliere, N., Murchu, L.O., Chien, E. (2011). "W32.Stuxnet Dossier." Symantec.
- ICS-CERT. (2010). Advisory ICSA-10-272-01.

---

### 2. Havex / Dragonfly (2014)

| Field | Detail |
|---|---|
| **Target** | Energy sector ICS (US, Europe) |
| **Technique** | OPC-based reconnaissance, trojanized ICS vendor installers |
| **Protocol** | OPC DA |
| **Impact** | Reconnaissance and foothold; no confirmed physical damage |
| **Persistence** | Long-term access (months) |
| **Detection** | Discovered by security researchers analyzing supply chain compromises |
| **CPSForge relevance** | Reconnaissance phase analogous to CPSForge's observation layer (ContextBuilder). Havex scanned for OPC servers and enumerated tags — equivalent to reading PLC data blocks to build an attack surface model. |

**Key technical details:**
- Havex's OPC module scanned local network for OPC DA servers
- Enumerated server names, CLSID values, server bandwidth, group names, and tag listings
- Trojanized installer approach = supply chain compromise (not CPSForge's threat model)
- No evidence of ICS process manipulation, only reconnaissance

**References:**
- Symantec. (2014). "Dragonfly: Cyberespionage Attacks Against Energy Suppliers."
- ICS-CERT. (2014). Alert ICS-ALERT-14-176-02A.

---

### 3. German Steel Mill Incident (2014)

| Field | Detail |
|---|---|
| **Target** | German steel mill blast furnace control systems |
| **Technique** | Spear-phishing → IT→OT lateral movement → HMI manipulation |
| **Protocol** | Unspecified SCADA/HMI protocols |
| **Impact** | Massive physical damage: blast furnace could not be shut down gracefully |
| **Persistence** | Single campaign, but extended dwell time in IT before OT pivot |
| **Detection** | Reported in BSI (German Federal Office for Information Security) annual report |
| **CPSForge relevance** | Demonstrates physical damage via control system manipulation. The IT→OT lateral movement pathway is the initial access phase that CPSForge's threat model assumes has already succeeded. |

**Key technical details:**
- Attackers had advanced knowledge of industrial control systems
- Multiple individual control components and entire systems failed
- Blast furnace could not be shut down in a controlled manner → massive damage
- Only second publicly confirmed case of cyber-physical damage (after Stuxnet)

**References:**
- BSI. (2014). "Die Lage der IT-Sicherheit in Deutschland 2014."
- Lee, R.M., Assante, M.J., Conway, T. (2014). "German Steel Mill Cyber Attack."

---

### 4. BlackEnergy / Ukraine Grid Attack (2015)

| Field | Detail |
|---|---|
| **Target** | 3 Ukrainian power distribution companies (Prykarpattyaoblenergo, Chernivtsioblenergo, Kyivoblenergo) |
| **Technique** | BlackEnergy3 malware, remote SCADA control via VPN, breaker tripping, KillDisk wiper, firmware overwrite of serial-to-Ethernet converters |
| **Protocol** | IEC 101, SCADA HMI direct interaction |
| **Impact** | ~225,000 customers lost power for 1-6 hours |
| **Persistence** | 6+ months reconnaissance; attack executed in ~30 minutes per target |
| **Detection** | Operators observed screens moving autonomously; manual recovery took hours |
| **CPSForge relevance** | Coordinated multi-target attack over ~30 minutes at supervisory timescale validates CPSForge's timing model. Attackers used existing SCADA tools (legitimate operator interfaces) rather than custom protocol attacks — similar to CPSForge using legitimate S7 protocol access. |

**Key technical details:**
- Attackers manually operated SCADA HMIs via stolen VPN credentials
- Opened breakers in sequence (30+ breakers across 3 utilities)
- KillDisk wiper destroyed workstation hard drives to delay recovery
- Firmware overwrite of serial-to-Ethernet converters = permanent denial of service on remote substations
- Phone flooding to delay customer-to-utility communication

**References:**
- E-ISAC/SANS. (2016). "Analysis of the Cyber Attack on the Ukrainian Power Grid."
- ICS-CERT. (2016). Alert IR-ALERT-H-16-056-01.

---

### 5. Industroyer / CrashOverride (2016)

| Field | Detail |
|---|---|
| **Target** | Ukrenergo (Ukrainian transmission grid) |
| **Technique** | Protocol-aware attack framework with built-in IEC 101, IEC 104, OPC DA, and IEC 61850 modules; automated breaker manipulation |
| **Protocol** | IEC 101, IEC 104, OPC DA, IEC 61850 |
| **Impact** | Power outage affecting part of Kyiv for ~1 hour |
| **Persistence** | Single automated campaign |
| **Detection** | Detected by power grid operators within hours |
| **CPSForge relevance** | **First ICS malware with built-in protocol implementations** — analogous to CPSForge's protocol-level S7 access. Industroyer directly spoke industrial protocols rather than tunneling through HMIs. CPSForge similarly uses python-snap7 to interact at the S7 protocol level. |

**Key technical details:**
- Modular design: main backdoor + 4 payloads (one per protocol)
- IEC 104 module sent automated breaker open/close sequences
- OPC DA module enumerated and manipulated tags
- Data wiper component for post-attack cleanup
- Automated attack sequence vs. BlackEnergy's manual operator approach

**References:**
- Dragos. (2017). "CrashOverride: Analysis of the Threat to Electric Grid Operations."
- ESET. (2017). "Industroyer: Win32/Industroyer."

---

### 6. TRITON / TRISIS (2017)

| Field | Detail |
|---|---|
| **Target** | Saudi petrochemical SIS (Schneider Electric Triconex 3008) |
| **Technique** | Zero-day exploitation of Triconex controller firmware, remote payload injection into SIS |
| **Protocol** | TriStation protocol (proprietary, reverse-engineered) |
| **Impact** | SIS tripped (safe shutdown); intended effect was SIS disablement during process attack |
| **Persistence** | Multi-hour reconnaissance before single critical write |
| **Detection** | SIS safe shutdown triggered investigation |
| **CPSForge relevance** | Targeted safety systems specifically. Demonstrates patient reconnaissance + single critical write strategy — analogous to CPSForge's "wait→attack" decision pattern where the LLM observes many cycles before acting. Also demonstrates the value of targeting safety systems (CPSForge's Enable flag attacks in Tier 2). |

**Key technical details:**
- TRITON injected malicious code into Triconex SIS controllers
- Intended to disable SIS while a separate (undiscovered) attack harmed the process
- SIS firmware vulnerability allowed arbitrary code execution
- Attackers spent significant time reverse-engineering the TriStation protocol
- Attack failed because of a code defect that caused the SIS to trip safe

**References:**
- Dragos. (2017). "TRISIS: Analyzing the Safety System Targeting Malware."
- FireEye/Mandiant. (2017). "Attackers Deploy New ICS Attack Framework, TRITON."

---

### 7. Oldsmar Water Treatment (2021)

| Field | Detail |
|---|---|
| **Target** | Oldsmar, Florida water treatment facility |
| **Technique** | Remote access via TeamViewer, sodium hydroxide (NaOH) setpoint change 100→11,100 ppm |
| **Protocol** | SCADA HMI direct interaction (TeamViewer) |
| **Impact** | Potentially lethal contamination; caught by operator within minutes |
| **Persistence** | Single write, immediately detected |
| **Detection** | Operator observed cursor moving on HMI screen |
| **CPSForge relevance** | **Simplest threat model** — direct value manipulation via remote access. Maps directly to CPSForge Tier 1 (single setpoint write). Demonstrates that even unsophisticated attacks on CPS can be dangerous. |

**Key technical details:**
- Attacker accessed TeamViewer on SCADA workstation
- Changed NaOH dosing from 100 ppm to 11,100 ppm (111× increase)
- Operator saw cursor moving and immediately reversed the change
- Multiple cybersecurity failures: shared credentials, direct internet exposure, outdated OS

**References:**
- Pinellas County Sheriff's Office. (2021). Press conference.
- CISA. (2021). Alert AA21-042A.

---

### 8. Colonial Pipeline (2021)

| Field | Detail |
|---|---|
| **Target** | Colonial Pipeline IT/OT systems |
| **Technique** | DarkSide ransomware on IT side |
| **Protocol** | IT-only (no direct OT compromise) |
| **Impact** | 5-day pipeline shutdown; fuel shortages across US East Coast |
| **Persistence** | Days |
| **Detection** | Detected by Colonial Pipeline IT staff |
| **CPSForge relevance** | Demonstrates IT→OT cascading impact without direct OT compromise. Pipeline had no direct OT attack, but uncertainty about OT integrity forced preventive shutdown. Highlights why CPS threat modeling must consider indirect impacts. |

**References:**
- CISA. (2021). Alert AA21-131A.
- Testimony before US Senate Committee on Homeland Security.

---

### 9. Industroyer2 (2022)

| Field | Detail |
|---|---|
| **Target** | Ukrainian power grid (Ukrenergo, during Russian invasion) |
| **Technique** | Updated Industroyer variant, IEC-104 protocol manipulation |
| **Protocol** | IEC-104 |
| **Impact** | Attack disrupted but intended to cause widespread power outage |
| **Persistence** | Single automated campaign |
| **Detection** | Detected and disrupted by CERT-UA with assistance from ESET |
| **CPSForge relevance** | Continued evolution of protocol-aware ICS malware. Demonstrates that nation-state actors continue investing in protocol-level ICS attack tools. |

**References:**
- ESET. (2022). "Industroyer2: Industroyer reloaded."
- CERT-UA. (2022). Advisory.

---

### 10. PIPEDREAM / Incontroller (2022)

| Field | Detail |
|---|---|
| **Target** | Cross-platform ICS (Schneider Modicon, OMRON Servo, OPC-UA) |
| **Technique** | Modular attack framework targeting multiple ICS protocols, PLC programming manipulation |
| **Protocol** | CODESYS, Modbus TCP, OPC-UA, OMRON FINS |
| **Impact** | Disrupted before deployment; capability to cause physical damage |
| **Persistence** | Reusable framework (not single-use) |
| **Detection** | Discovered by Dragos, Mandiant, Schneider Electric, CISA before deployment |
| **CPSForge relevance** | **State-sponsored general-purpose ICS attack toolkit** — most comparable to CPSForge's framework concept. PIPEDREAM includes PLC logic modification capability (Tier 3) and protocol-level data manipulation (Tier 1). CPSForge is the research counterpart for studying these capabilities. |

**Key technical details:**
- CHERNOVITE (threat group) built modular toolkit with 5 tools
- TAGRUN: OPC-UA scanner and manipulator
- CODECALL: Modbus/CODESYS protocol interaction
- OMSHELL: OMRON servo drive manipulation via FINS/HTTP
- MOUSEHOLE: Windows-based exploitation tool
- Capable of PLC program upload/download, logic modification, process disruption

**References:**
- Dragos. (2022). "CHERNOVITE's PIPEDREAM."
- CISA. (2022). Advisory AA22-103A.
- Mandiant. (2022). "INCONTROLLER: New State-Sponsored Cyber Attack Tools."

---

### 11. Unitronics PLC Attacks (2023)

| Field | Detail |
|---|---|
| **Target** | US water utilities, Unitronics Vision PLCs |
| **Technique** | Default credentials on internet-exposed PLCs, HMI defacement |
| **Protocol** | PCOM (Unitronics proprietary) |
| **Impact** | HMI defacement; potential process manipulation (not confirmed) |
| **Persistence** | Opportunistic, single writes |
| **Detection** | Operators noticed defaced HMIs |
| **CPSForge relevance** | Demonstrates real-world PLC targeting with minimal sophistication. PLCs exposed directly to internet with default credentials — simplest possible access model. Validates that PLC-level attacks are not theoretical. |

**References:**
- CISA. (2023). Advisory AA23-335A.
- WaterISAC. (2023). Advisory.

---

## Cross-Incident Analysis

### Key Patterns

1. **All major incidents operate at supervisory timescale** (seconds to weeks,
   not PLC scan cycle time) — validates CPSForge's 500ms polling and
   multi-second decision intervals.

2. **Stuxnet is the only precedent for combined MitM + logic modification** —
   directly motivates CPSForge's three-tier threat model.

3. **Progression of capability**:
   reconnaissance → data observation → data manipulation → logic modification → safety system targeting.
   CPSForge covers the middle three tiers.

4. **Protocol-level access is the dominant attack vector** for sophisticated
   actors (Stuxnet, Industroyer, PIPEDREAM). CPSForge's S7 protocol access
   via python-snap7 is representative of this realistic threat model.

5. **Safety system targeting** (TRITON) is the most dangerous escalation.
   CPSForge's Enable flag attacks (Tier 2) explore this boundary.

### Mapping to CPSForge Threat Tiers

| Tier | CPSForge Component | Real-World Analogues |
|---|---|---|
| **Tier 1: I/O MitM** | OnlineMITMAttacker | Oldsmar (value change), BlackEnergy (breaker trip), Industroyer (protocol commands) |
| **Tier 2: Deep State** | DeepStateMITMAttacker | Stuxnet DB890 writes, TRITON SIS manipulation, PIPEDREAM state manipulation |
| **Tier 3: Logic Gen** | LogicAnalyzer | Stuxnet OB1/OB35 replacement, PIPEDREAM PLC program upload |
| **Defense** | StateConsistencyChecker + CodeReviewDefender | TRITON SIS trip detection, Industroyer recovery procedures |

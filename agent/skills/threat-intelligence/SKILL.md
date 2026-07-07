---
name: threat-intelligence
description: Domain knowledge regarding ClickFix social engineering techniques, JavaScript obfuscation (obfuscator.io), and malicious DOM behavior. Use this skill when analyzing suspect payloads or DOM lures.
---

# Threat Intelligence: Malware & Social Engineering

When auditing the `raw_dom` or clipboard payloads of a suspected compromised site, specialized threat intelligence is required to spot malicious behavior disguised as legitimate code or user interactions.

## 1. ClickFix / ClearFake Social Engineering
"ClickFix" (often associated with the "ClearFake" campaign) is a highly prevalent attack vector targeting users directly, bypassing traditional browser exploits.

### Attack Methodology
1. **Compromise**: Attackers compromise legitimate websites (often WordPress sites).
2. **Injection**: They inject malicious JavaScript into the victim site's DOM.
3. **The Lure**: The injected script overlays a fake, highly convincing modal. Common lures:
   - **Fake CAPTCHA**: "Please verify you are human by pressing Win+R, Ctrl+V, Enter."
   - **Fake Browser Update**: "Your Google Chrome is out of date. Run this fix."
   - **Fake Font Missing**: "The 'Hoefler Text' font wasn't found. Copy this command."
   - **Fake Error**: "Microsoft Word encountered an error opening this document."
4. **The Execution**: The modal contains a button (e.g., "Verify") that secretly writes a malicious command to the user's system clipboard using `navigator.clipboard.writeText()` or a hidden `textarea`.
5. **The Payload**: The user is socially engineered into pasting the command into a terminal.

### Key Identifiers
- **Lure Text**: Instructions to press `Windows Key + R`, `Ctrl + V`, `Enter`.
- **Payload Targets**: Shell commands targeting `cmd.exe`, `powershell.exe`, `wscript.exe`.

## 2. Obfuscator Patterns
Malicious actors heavily obfuscate their JavaScript injectors and PowerShell payloads.

### JavaScript Obfuscation (e.g., Obfuscator.io)
- **String Array Mapping**: All literal strings are Base64/Hex encoded into a massive array.
- **Proxy Functions**: Strings are retrieved by calling a proxy function (e.g., `_0x1a2b(150)`).
- **Control Flow Flattening**: The logic is chopped into chunks inside a `switch` wrapped in a `while(!![])` loop.
- **Dead Code Injection**: Random code blocks inserted to alter file hashes.

### PowerShell Payload Obfuscation
- **Base64 Encoding**: `[System.Convert]::FromBase64String('ZXZpbA==')`
- **Backtick Obfuscation**: Backticks escape characters: `p\`o\`w\`e\`r\`s\`h\`e\`l\`l.exe`.
- **Caret Obfuscation (CMD)**: Carets escape characters: `c^m^d.exe`.
- **Parameter Aliasing**: `-nop` (NoProfile), `-ep bypass` (ExecutionPolicy Bypass).

## 3. Malicious JavaScript execution
- **Dynamic Execution**: Executing strings via `eval(atob('...'))` or `setTimeout("code", 0)`.
- **Dynamic Script Injection**: Creating a script element and pointing its `src` to an attacker-controlled domain.
- **Clipboard Hijacking**: Hooking into `window.oncopy` to silently modify the clipboard, or using hidden textareas.

 ## Reference Files
- [Deobfuscating JavaScript Malware](references/deobfuscating-javascript-malware.md): Comprehensive guidelines for reversing encoding layers and string manipulation in malicious JavaScript.
- [Deobfuscating PowerShell Malware](references/deobfuscating-powershell-obfuscated-malware.md): Systematically deobfuscate multi-layer PowerShell malware using AST analysis, dynamic execution tracking, and string decryption.
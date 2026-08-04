import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { SomaError } from "./errors.mjs";

let resolvedPowerShell = null;

// Never spawn a bare "powershell.exe": Windows resolves an unqualified image
// name against the current working directory before PATH, so a dropped binary
// in the cwd would receive DPAPI plaintext on stdin. Resolve the absolute
// system path, or refuse to run at all.
export function resolveWindowsPowerShell() {
  if (resolvedPowerShell) return resolvedPowerShell;
  const systemRoot = process.env.SystemRoot || process.env.SYSTEMROOT || process.env.windir;
  if (!systemRoot || !isAbsolute(systemRoot)) {
    throw new SomaError("Windows system root is not resolvable", 8, "WINDOWS_SHELL_UNRESOLVED", {
      cause: "SystemRoot environment variable missing or not absolute"
    });
  }
  const candidate = join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  if (!existsSync(candidate)) {
    throw new SomaError("Windows PowerShell was not found at its system path", 8, "WINDOWS_SHELL_UNRESOLVED", {
      cause: candidate
    });
  }
  resolvedPowerShell = candidate;
  return resolvedPowerShell;
}

// PowerShell startup on a cold or loaded machine is unpredictable -- a
// continuous-integration runner can take far longer to spawn it than a
// developer's desktop. A single fixed deadline therefore fails for reasons that
// have nothing to do with the operation being attempted.
//
// Both operations that use this are idempotent: reading an ACL, or setting one
// to a value it may already hold. Retrying is safe, and the alternative is a
// build that fails on machine speed.
const POWERSHELL_ATTEMPT_TIMEOUTS_MS = [15000, 45000];

function spawnPowerShell(script, input) {
  let last = null;
  for (const timeout of POWERSHELL_ATTEMPT_TIMEOUTS_MS) {
    const result = spawnSync(resolveWindowsPowerShell(), ["-NoProfile", "-NonInteractive", "-Command", script], {
      input,
      encoding: "utf8",
      windowsHide: true,
      timeout,
      maxBuffer: 1024 * 1024
    });
    // Only a timeout is retried. A non-zero exit is a real refusal and repeating
    // it would just take longer to report the same answer.
    if (result.error?.code !== "ETIMEDOUT") return result;
    last = result;
  }
  return last;
}

function powershellJson(script, input) {
  const result = spawnPowerShell(script, input);
  if (result.error || result.status !== 0) {
    throw new SomaError("Windows ACL operation failed", 8, "WINDOWS_ACL_FAILED", {
      cause: result.error?.message || result.stderr.trim() || `PowerShell exited ${result.status}`
    });
  }
  return result.stdout.trim() ? JSON.parse(result.stdout) : null;
}

export async function restrictStatePath(file) {
  if (process.platform !== "win32") {
    await chmod(file, 0o600);
    return { profile: "posix-owner-only-v1" };
  }
  const script = [
    "$ErrorActionPreference='Stop'",
    "$path=[Console]::In.ReadToEnd()",
    "$identity=[Security.Principal.WindowsIdentity]::GetCurrent()",
    "$user=$identity.User",
    "$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')",
    "$item=Get-Item -LiteralPath $path -Force",
    "$currentAcl=$item.GetAccessControl()",
    "$currentOwner=$currentAcl.Owner",
    "$ownerMatches=($currentOwner -eq $identity.Name -or $currentOwner -eq $user.Value)",
    "if(-not $ownerMatches){$takeownOutput=& takeown.exe /F $path 2>&1;if($LASTEXITCODE -ne 0){throw ('takeown failed: '+($takeownOutput -join ' '))};$item=Get-Item -LiteralPath $path -Force}",
    "$acl=$item.GetAccessControl()",
    "$acl.SetAccessRuleProtection($true,$false)",
    "foreach($rule in @($acl.Access)){$acl.RemoveAccessRuleSpecific($rule)}",
    "$none=[Security.AccessControl.InheritanceFlags]::None",
    "$prop=[Security.AccessControl.PropagationFlags]::None",
    "$type=[Security.AccessControl.AccessControlType]::Allow",
    "$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($user,'FullControl',$none,$prop,$type)))",
    "$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,'FullControl',$none,$prop,$type)))",
    "$item.SetAccessControl($acl)",
    "[ordered]@{profile='windows-owner-system-only-v1';user_sid=$user.Value}|ConvertTo-Json -Compress"
  ].join(";");
  return powershellJson(script, file);
}

export async function restrictStateRoot(directory) {
  if (process.platform !== "win32") {
    await chmod(directory, 0o700);
    return { profile: "posix-owner-only-v1" };
  }
  const script = [
    "$ErrorActionPreference='Stop'",
    "$path=[Console]::In.ReadToEnd()",
    "$user=[Security.Principal.WindowsIdentity]::GetCurrent().User",
    "$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')",
    "$acl=New-Object Security.AccessControl.DirectorySecurity",
    "$acl.SetAccessRuleProtection($true,$false)",
    "$acl.SetOwner($user)",
    "$inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'",
    "$prop=[Security.AccessControl.PropagationFlags]::None",
    "$type=[Security.AccessControl.AccessControlType]::Allow",
    "$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($user,'FullControl',$inherit,$prop,$type)))",
    "$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,'FullControl',$inherit,$prop,$type)))",
    "$currentAcl=Get-Acl -LiteralPath $path",
    "$currentName=[Security.Principal.WindowsIdentity]::GetCurrent().Name",
    "$currentOwnerMatches=($currentAcl.Owner -eq $currentName -or $currentAcl.Owner -eq $user.Value)",
    "if(-not $currentAcl.AreAccessRulesProtected -or -not $currentOwnerMatches){Set-Acl -LiteralPath $path -AclObject $acl}",
    "$runPath=[IO.Path]::GetFullPath((Join-Path $path 'run'))",
    "$items=Get-ChildItem -LiteralPath $path -Force -Recurse|Where-Object{-not(-not $_.PSIsContainer -and $_.Directory.FullName -eq $runPath -and $_.Extension -eq '.lock')}",
    "$ownerMismatch=$false;foreach($item in $items){$itemOwner=(Get-Acl -LiteralPath $item.FullName).Owner;if($itemOwner -ne $currentName -and $itemOwner -ne $user.Value){$ownerMismatch=$true;break}}",
    "if($ownerMismatch){$takeownOutput=& takeown.exe /F $path /R /D Y 2>&1;if($LASTEXITCODE -ne 0){throw ('takeown failed: '+($takeownOutput -join ' '))}}",
    "foreach($item in $items){$itemAcl=$item.GetAccessControl();$itemAcl.SetAccessRuleProtection($true,$false);foreach($rule in @($itemAcl.Access)){$itemAcl.RemoveAccessRuleSpecific($rule)};$itemInherit=if($item.PSIsContainer){$inherit}else{[Security.AccessControl.InheritanceFlags]::None};$itemAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($user,'FullControl',$itemInherit,$prop,$type)));$itemAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,'FullControl',$itemInherit,$prop,$type)));$item.SetAccessControl($itemAcl)}",
    "[ordered]@{profile='windows-owner-system-only-v1';user_sid=$user.Value}|ConvertTo-Json -Compress"
  ].join(";");
  return powershellJson(script, directory);
}

export function inspectStateRootPermissions(directory) {
  if (process.platform !== "win32") {
    return {
      profile: "posix-owner-only-v1-development-only",
      protected: true,
      owner_matches: true,
      unauthorized_allow_count: 0,
      unsafe_path_count: 0,
      checked_path_count: 1
    };
  }
  const script = [
    "$ErrorActionPreference='Stop'",
    "$path=[Console]::In.ReadToEnd()",
    "$identity=[Security.Principal.WindowsIdentity]::GetCurrent()",
    "$user=$identity.User.Value",
    "$name=$identity.Name",
    "$allowed=@($user,'S-1-5-18')",
    "$rootAcl=Get-Acl -LiteralPath $path",
    "$rootOwnerMatches=($rootAcl.Owner -eq $name -or $rootAcl.Owner -eq $user)",
    "$items=@((Get-Item -LiteralPath $path))+@(Get-ChildItem -LiteralPath $path -Force -Recurse)",
    "$badAllowCount=0",
    "$unsafePathCount=0",
    "foreach($item in $items){$itemAcl=Get-Acl -LiteralPath $item.FullName;$ownerMatches=($itemAcl.Owner -eq $name -or $itemAcl.Owner -eq $user);$bad=@($itemAcl.Access|Where-Object{$_.AccessControlType -eq 'Allow' -and $allowed -notcontains $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value});$badAllowCount+=$bad.Count;if(-not $ownerMatches -or $bad.Count -gt 0){$unsafePathCount++}}",
    "[ordered]@{profile='windows-owner-system-only-v1';protected=$rootAcl.AreAccessRulesProtected;owner=$rootAcl.Owner;owner_matches=$rootOwnerMatches;current_user_sid=$user;unauthorized_allow_count=$badAllowCount;unsafe_path_count=$unsafePathCount;checked_path_count=$items.Count}|ConvertTo-Json -Compress"
  ].join(";");
  return powershellJson(script, directory);
}

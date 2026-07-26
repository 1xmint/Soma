import { spawnSync } from "node:child_process";
import { chmod } from "node:fs/promises";
import { SomaError } from "./errors.mjs";

function powershellJson(script, input) {
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    input,
    encoding: "utf8",
    windowsHide: true,
    timeout: 15000,
    maxBuffer: 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    throw new SomaError("Windows ACL operation failed", 8, "WINDOWS_ACL_FAILED", {
      cause: result.error?.message || result.stderr.trim() || `PowerShell exited ${result.status}`
    });
  }
  return result.stdout.trim() ? JSON.parse(result.stdout) : null;
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
    "$items=Get-ChildItem -LiteralPath $path -Force -Recurse",
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

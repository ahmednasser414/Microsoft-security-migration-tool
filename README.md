# GBG Tool for Migration

`Migrate-script.ps1` starts a GBG-branded local browser webpage for selected Microsoft Entra and Intune Security Policy Migration using interactive Microsoft Graph sign-in. No app registration, client ID, client secret, certificate, or credentials file is used.

The tool provides four workload choices:

- **Conditional Access**: selected policies only. Users retain their UPN local part and use the destination tenant's default verified domain, for example `x@source.com` becomes `x@destination.com`. Groups are mapped by exact display name. New policies default to report-only mode.
- **Custom Detection Rules**: selected Defender XDR custom detection rules only, using source and destination interactive browser sign-in. Sentinel analytics rules are explicitly excluded.
- **Antivirus Settings**: selected Intune Endpoint Security Antivirus policies only.
- **ASR Rules**: selected Intune Endpoint Security Attack Surface Reduction policies only.

Every working workload shows a checkbox list after source sign-in. Only selected policies are migrated, and the results table identifies created and not-created policies with the reason.

## Requirements

Install the Microsoft Graph PowerShell authentication module once in PowerShell 7 on Windows:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

You must sign in interactively as an administrator in each tenant. Consent is requested in the browser during each sign-in.

| Tenant | Delegated Microsoft Graph permissions |
| --- | --- |
| Source | `Policy.Read.All`, `Application.Read.All`, `Directory.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementEndpointSecurity.Read.All`, `CustomDetection.Read.All` |
| Destination | `Policy.ReadWrite.ConditionalAccess`, `Application.Read.All`, `Directory.Read.All`, `DeviceManagementConfiguration.ReadWrite.All`, `DeviceManagementEndpointSecurity.ReadWrite.All`, `CustomDetection.ReadWrite.All` |

## Run the Browser App

```powershell
.\Migrate-script.ps1
```

The script opens a local `127.0.0.1` webpage in the default browser. Select **Sign In to Source** and **Sign In to Destination** separately, choosing the correct tenant account in each Microsoft browser prompt. The tool automatically captures each signed-in tenant ID and default verified domain. The migration button remains unavailable until both sign-ins succeed.

After the source sign-in completes, use the workload's **Policies to Migrate** table to choose the policies to copy. All policies are selected by default; use **Select All** or **Clear All** as needed.

## CLI mode

Use `-NoGui` only when a GUI is not suitable:

```powershell
.\Migrate-script.ps1 `
  -NoGui `
  -SourceTenantId '<source-tenant-guid>' `
  -TargetTenantId '<destination-tenant-guid>' `
  -DefaultState ReportOnly
```

Use `-DefaultState ReportOnly`, `Enabled`, or `Disabled` to choose the state for created policies. Use `-WhatIf` to preview policy creates. Disabled source policies are excluded unless `-IncludeDisabledPolicies` is supplied.

## Migration behavior and limits

- Users must already exist in the destination as `localpart@destination-default-domain`.
- Groups must already exist in the destination with the same exact display name. Duplicate target group names are rejected because they are ambiguous.
- Antivirus and ASR use Microsoft Graph beta Intune Endpoint Security configuration-policy APIs. After creating a selected policy, the tool maps each group assignment to one destination group with the same exact display name. A missing or duplicate destination group is reported for that policy. Review migrated settings and assignments before production rollout.
- Named locations are not copied automatically. A policy that refers to a missing same-named destination location is marked **Not created** in the results table. Create the location manually in the destination, then rerun the policy migration.
- Authentication contexts must already exist in the destination with the same display name before referenced policies can be created. Policies using Terms of Use are listed as not created because their documents and mappings require manual recreation.
- Create custom controls in the destination first, then use `-CustomControlMapPath` with a JSON object that maps source IDs to destination IDs, for example `{ "source-id": "destination-id" }`.
- Authentication strengths, enterprise applications, device filters, and other referenced resources must exist in the destination with compatible configuration. Review all report-only policies before enabling enforcement.
- Custom Detection Rules use delegated work-account consent. The source administrator needs `CustomDetection.Read.All`; the destination administrator needs `CustomDetection.ReadWrite.All`. The signed-in administrators must also hold the applicable Defender XDR RBAC roles. The credentials included in the uploaded reference note must be revoked and rotated; never place secrets in a script or repository.

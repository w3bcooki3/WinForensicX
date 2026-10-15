@{
    # WinForensicX lint policy. Rules excluded below are deliberate design choices, each justified here
    # so a reviewer can see the reasoning rather than guess. Everything else is enforced.
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Write-WfxConsole is the single, intentional place the tool writes colored CLI output; it is the
        # project's console abstraction (honors -Quiet). Suppressing Write-Host there is by design.
        'PSAvoidUsingWriteHost',

        # Many probes are best-effort by design (a registry key / file / cmdlet may simply be absent or
        # access-denied). Those failures are either swallowed on purpose or recorded as a collection gap
        # via Invoke-WfxStep. Empty catches are intentional graceful degradation, not missed errors.
        'PSAvoidUsingEmptyCatchBlock',

        # Remote triage bootstraps the collectors inside a WinRM session by dot-sourcing the module's own
        # source (Get-WfxPortableSource) via Invoke-Expression. The input is the tool's own code, never
        # user data. This is the one controlled, documented use.
        'PSAvoidUsingInvokeExpression',

        # The toolkit is strictly read-only triage. New-WfxCase/Complete-WfxCase create an output folder
        # for evidence; adding ShouldProcess prompts to a non-interactive IR tool would hurt more than help.
        'PSUseShouldProcessForStateChangingFunctions',

        # Several collectors use their parameters only inside Invoke-WfxStep script blocks (child scope),
        # which this rule cannot see, producing false positives (ExtraPath, MaxReadKB, MaxPerLog, etc.).
        'PSReviewUnusedParameter',

        # 'Event' is a domain term here (an event-log record / an audit event name), used as a parameter
        # that locally shadows the automatic variable by design. '$home' (a true hazard) was renamed.
        'PSAvoidAssignmentToAutomaticVariable',

        # A few helpers intentionally return collections and read naturally as plurals
        # (Get-WfxUserHives, Get-WfxRedactedHits, Get-WfxGap).
        'PSUseSingularNouns'
    )
}

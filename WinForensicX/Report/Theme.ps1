# Shared look for the HTML pages that are built in PowerShell (the in-tool help page): the same tokens,
# masthead and mark as the case report, fleet report and Explore views, so they read as one product.
# System fonts only (self-contained / offline). Light by default, full dark theme.

function Get-WfxMarkSvg {
    <# The WinForensicX mark (evidence-photo frame, X, lens) as inline SVG. #>
    param([string]$Class = '', [string]$Lens = 'var(--band)')
    '<svg class="' + $Class + '" viewBox="0 0 64 64" aria-hidden="true"><path d="M6 20V6h14M44 6h14v14M58 44v14H44M20 58H6V44" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="square"/><path d="M20 20l24 24M44 20L20 44" fill="none" stroke="currentColor" stroke-width="6"/><circle cx="32" cy="32" r="9" fill="' + $Lens + '" stroke="currentColor" stroke-width="5"/><circle cx="32" cy="32" r="3" fill="currentColor"/></svg>'
}

function Get-WfxThemeCss {
    @'
*,*::before,*::after{box-sizing:border-box;font-variant-ligatures:none;font-feature-settings:"calt" 0,"liga" 0,"clig" 0}
:root{
  --page:#FFFFFF;--alt:#F5F6F8;--ink:#17202C;--ink2:#4E5967;--ink3:#7B8591;--line:#D3D8DE;--line2:#E6E9ED;--link:#0B57A4;
  --band:#14233A;--band-ink:#F1F4F8;--band-dim:#A9B6C6;
  --crit:#9B1C1C;--high:#C2410C;--med:#A16207;--low:#2B6CB0;--info:#6B7280;
  --sans:"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
  --mono:"Cascadia Mono","Cascadia Code",Consolas,"SF Mono",Menlo,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--page:#14181D;--alt:#1A1F25;--ink:#E3E7EC;--ink2:#A4AEBA;--ink3:#7D8793;--line:#333B45;--line2:#262D35;--link:#7CB1EC;--band:#0D141D;--crit:#F07171;--high:#F59056;--med:#E2B04A;--low:#7FB0E6;--info:#9AA3AE}}
:root[data-theme=dark]{--page:#14181D;--alt:#1A1F25;--ink:#E3E7EC;--ink2:#A4AEBA;--ink3:#7D8793;--line:#333B45;--line2:#262D35;--link:#7CB1EC;--band:#0D141D;--crit:#F07171;--high:#F59056;--med:#E2B04A;--low:#7FB0E6;--info:#9AA3AE}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--ink);font:14.5px/1.55 var(--sans)}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--link);outline-offset:2px}
h1,h2,h3{margin:0;font-weight:600}
.mono{font-family:var(--mono);font-size:12.5px}
.mast{background:var(--band);color:var(--band-ink)}
.mast .in{max-width:960px;margin:0 auto;padding:16px 24px 26px}
.brandrow{display:flex;align-items:center;gap:10px;font-size:13px;color:var(--band-dim)}
.brandrow svg{width:22px;height:22px;color:var(--band-ink)}
.brandrow b{color:var(--band-ink);font-weight:600;font-size:14px}
.brandrow .tools{margin-left:auto}
.mbtn{font:inherit;font-size:12.5px;color:var(--band-ink);background:transparent;border:1px solid rgba(255,255,255,.28);border-radius:3px;padding:3px 10px;cursor:pointer}
.mbtn:hover{border-color:rgba(255,255,255,.6)}
.mast h1{font-size:30px;line-height:1.15;margin-top:26px}
.mast p{color:var(--band-dim);margin:8px 0 0;max-width:72ch}
'@
}

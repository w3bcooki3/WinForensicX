# Shared "Beacon" design system for the HTML report and guide, so they look like one product.
# Decision-first, high-readability: light by default, full dark theme, system fonts (self-contained/offline).

function Get-WfxThemeCss {
    @'
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f6f7f9;--card:#ffffff;--card2:#fcfcfe;--ink:#0f1623;--ink2:#1f2a3a;--dim:#5b6676;--faint:#8a94a4;
  --line:#e7eaef;--line2:#dfe3ea;--acc:#4f46e5;--acc2:#eef0fe;
  --crit:#e11d48;--high:#ea580c;--med:#d97706;--low:#2563eb;--info:#64748b;--ok:#15a06b;
  --sans:"Inter","Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,"SFMono-Regular","SF Mono",Menlo,Consolas,monospace;
  --sh:0 1px 2px rgba(11,24,48,.04),0 8px 24px -14px rgba(11,24,48,.13);
  --sh2:0 2px 4px rgba(11,24,48,.06),0 16px 38px -18px rgba(11,24,48,.2);
  --r:14px;
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#0a0c10;--card:#12151d;--card2:#161a24;--ink:#e9edf3;--ink2:#ffffff;--dim:#95a0b0;--faint:#667183;
  --line:#20262f;--line2:#2c3340;--acc:#7c83ff;--acc2:#1a1f38;
  --crit:#ff4766;--high:#ff9340;--med:#ffd24a;--low:#5e8fff;--info:#7d8798;--ok:#2ee6a6;
  --sh:0 1px 2px rgba(0,0,0,.3),0 10px 26px -16px rgba(0,0,0,.6);
  --sh2:0 2px 6px rgba(0,0,0,.4),0 18px 40px -20px rgba(0,0,0,.7);
}}
:root[data-theme=dark]{
  --bg:#0a0c10;--card:#12151d;--card2:#161a24;--ink:#e9edf3;--ink2:#ffffff;--dim:#95a0b0;--faint:#667183;
  --line:#20262f;--line2:#2c3340;--acc:#7c83ff;--acc2:#1a1f38;
  --crit:#ff4766;--high:#ff9340;--med:#ffd24a;--low:#5e8fff;--info:#7d8798;--ok:#2ee6a6;
  --sh:0 1px 2px rgba(0,0,0,.3),0 10px 26px -16px rgba(0,0,0,.6);
  --sh2:0 2px 6px rgba(0,0,0,.4),0 18px 40px -20px rgba(0,0,0,.7);
}
html{-webkit-text-size-adjust:100%}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.55;
  letter-spacing:-.01em;-webkit-font-smoothing:antialiased}
.mono{font-family:var(--mono)}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
h1,h2,h3,h4{font-weight:700;letter-spacing:-.02em}
kbd{font-family:var(--mono);font-size:.82em;background:var(--card2);border:1px solid var(--line2);
  border-bottom-width:2px;border-radius:5px;padding:1px 6px;color:var(--ink2)}
::selection{background:var(--acc);color:#fff}
.bg-Critical{background:var(--crit)}.bg-High{background:var(--high)}.bg-Medium{background:var(--med)}.bg-Low{background:var(--low)}.bg-Info{background:var(--info)}
.fg-Critical{color:var(--crit)}.fg-High{color:var(--high)}.fg-Medium{color:var(--med)}.fg-Low{color:var(--low)}.fg-Info{color:var(--info)}
/* top bar (shared) */
.bar{display:flex;align-items:center;gap:13px;margin-bottom:24px}
.bz{width:34px;height:34px;border-radius:10px;background:var(--acc);color:#fff;display:grid;place-items:center;
  font-weight:800;box-shadow:0 6px 16px -6px var(--acc);flex:none}
.bn{font-weight:750;font-size:16px;letter-spacing:-.02em}.bn span{color:var(--faint);font-weight:500;font-size:12.5px;margin-left:7px}
.bar .sp{flex:1}
.chip{font-size:13px;color:var(--ink2);background:var(--card);border:1px solid var(--line2);border-radius:9px;
  padding:7px 12px;box-shadow:var(--sh);white-space:nowrap}
.chip b{color:var(--acc)}
.gbtn{font-size:13px;color:var(--dim);background:var(--card);border:1px solid var(--line2);border-radius:9px;
  padding:7px 13px;cursor:pointer;box-shadow:var(--sh)}
.gbtn:hover{color:var(--ink2);border-color:var(--acc)}
'@
}

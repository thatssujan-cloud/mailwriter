#!/usr/bin/env python3
"""Generate css/utils.css — a tiny hand-rolled utility layer that replaces the
Tailwind CDN. Only classes actually present in index.html / js are emitted, so
the site stays simple and dependency-free while every existing markup contract
(class names toggled by JS included) keeps working."""
import re

P = '/workspace/index.html'
s = open(P, encoding='utf-8').read()

tokens = set()
for m in re.finditer(r'class="([^"]*)"', s):
    for t in m.group(1).split():
        tokens.add(t)
for m in re.finditer(r"classList\.(?:add|remove|toggle)\(([^)]*)\)", s):
    for t in re.findall(r"'([^']+)'", m.group(1)):
        for x in t.split():
            tokens.add(x)
# classes toggled at runtime by js/app.js
for t in ['hidden', 'is-active', 'ld-open', 'ld-visible', 'ld-spinner', 'open']:
    tokens.add(t)

PAL = {
 'ink':{50:'#f8fafc',100:'#f1f5f9',200:'#e2e8f0',300:'#cbd5e1',400:'#94a3b8',500:'#64748b',600:'#475569',700:'#334155',800:'#1e293b',900:'#0f172a',950:'#020617'},
 'slate':{50:'#f8fafc',100:'#f1f5f9',200:'#e2e8f0',300:'#cbd5e1',400:'#94a3b8',500:'#64748b',600:'#475569',700:'#334155',800:'#1e293b',900:'#0f172a'},
 'brand':{50:'#eff6ff',100:'#dbeafe',200:'#bfdbfe',300:'#93c5fd',400:'#60a5fa',500:'#3b82f6',600:'#2563eb',700:'#1d4ed8',800:'#1e40af',900:'#1e3a8a'},
 'forest':{50:'#ecfdf5',100:'#d1fae5',200:'#a7f3d0',300:'#6ee7b7',400:'#34d399',500:'#10b981',600:'#059669',700:'#047857',800:'#065f46',900:'#064e3b'},
 'emerald':{500:'#10b981'},
 'amber':{50:'#fffbeb',100:'#fef3c7',200:'#fde68a',300:'#fcd34d',400:'#fbbf24',500:'#f59e0b',600:'#d97706',700:'#b45309',800:'#92400e'},
 'clay':{600:'#ea580c'},
 'rose':{50:'#fff1f2',100:'#ffe4e6',200:'#fecdd3',300:'#fda4af',400:'#fb7185',500:'#f43f5e',600:'#e11d48',700:'#be123c'},
 'white':{'':'#ffffff'}, 'black':{'':'#000000'},
}
SP = {0:'0px',0.5:'2px',1:'4px',1.5:'6px',2:'8px',2.5:'10px',3:'12px',3.5:'14px',4:'16px',5:'20px',6:'24px',7:'28px',8:'32px',9:'36px',10:'40px',12:'48px',14:'56px',16:'64px'}
FSZ = {'xs':'0.75rem','sm':'0.875rem','base':'1rem','lg':'1.125rem','xl':'1.25rem','2xl':'1.5rem','3xl':'1.875rem','4xl':'2.25rem','5xl':'3rem','6xl':'3.75rem'}

def esc(t): return re.sub(r'([^\w-])', r'\\\1', t)

def sp(v):
    try: return SP.get(float(v))
    except (TypeError, ValueError): return None

def color_val(prop_base):
    """prop_base like 'ink-950/60' -> css color or None"""
    base, alpha = prop_base, None
    if '/' in prop_base:
        base, a = prop_base.split('/', 1)
        try: alpha = int(a)
        except ValueError: alpha = None
    parts = base.split('-')
    fam = PAL.get('-'.join(parts[:-1]))
    if not fam: return None
    col = fam.get(parts[-1], fam.get(''))
    if col is None: return None
    if alpha is not None and col.startswith('#'):
        r_,g_,b_ = int(col[1:3],16),int(col[3:5],16),int(col[5:7],16)
        col = f'rgba({r_},{g_},{b_},{alpha/100})'
    return col

SIMPLE = {
 'flex':'display:flex','inline-flex':'display:inline-flex','grid':'display:grid','block':'display:block',
 'inline-block':'display:inline-block','inline':'display:inline','table':'display:table','contents':'display:contents',
 'hidden':'display:none !important','static':'position:static','fixed':'position:fixed',
 'absolute':'position:absolute','relative':'position:relative','sticky':'position:sticky',
 'flex-row':'flex-direction:row','flex-col':'flex-direction:column','flex-wrap':'flex-wrap:wrap','flex-1':'flex:1 1 0%',
 'flex-none':'flex:none','shrink-0':'flex-shrink:0','grow':'flex-grow:1','grow-0':'flex-grow:0',
 'items-center':'align-items:center','items-start':'align-items:flex-start','items-end':'align-items:flex-end','items-baseline':'align-items:baseline','items-stretch':'align-items:stretch',
 'justify-center':'justify-content:center','justify-between':'justify-content:space-between','justify-end':'justify-content:flex-end','justify-start':'justify-content:flex-start',
 'self-center':'align-self:center','text-left':'text-align:left','text-center':'text-align:center','text-right':'text-align:right',
 'truncate':'overflow:hidden;text-overflow:ellipsis;white-space:nowrap',
 'overflow-hidden':'overflow:hidden','overflow-auto':'overflow:auto','overflow-x-auto':'overflow-x:auto','overflow-y-auto':'overflow-y:auto',
 'whitespace-nowrap':'white-space:nowrap','whitespace-pre-wrap':'white-space:pre-wrap','break-words':'overflow-wrap:break-word',
 'cursor-pointer':'cursor:pointer','cursor-not-allowed':'cursor:not-allowed','cursor-default':'cursor:default','select-none':'user-select:none',
 'pointer-events-none':'pointer-events:none','pointer-events-auto':'pointer-events:auto','list-none':'list-style:none',
 'resize-y':'resize:vertical','resize-none':'resize:none','uppercase':'text-transform:uppercase','normal-case':'text-transform:none',
 'italic':'font-style:italic','not-italic':'font-style:normal','underline':'text-decoration-line:underline','no-underline':'text-decoration-line:none',
 'sr-only':'position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border-width:0',
 'not-sr-only':'position:static;width:auto;height:auto;padding:0;margin:0;overflow:visible;clip:auto;white-space:normal',
 'object-cover':'object-fit:cover','align-middle':'vertical-align:middle','align-top':'vertical-align:top',
 'transition':'transition-property:color,background-color,border-color,box-shadow,opacity;transition-duration:150ms',
 'transition-colors':'transition-property:color,background-color,border-color;transition-duration:150ms',
 'transition-none':'transition-property:none',
 'animate-spin':'animation:spin 1s linear infinite','animate-pulse':'animation:pulse 2s cubic-bezier(0.4,0,0.6,1) infinite',
 'shadow-card':'box-shadow:none','shadow-lift':'box-shadow:none','shadow-lg':'box-shadow:none','shadow':'box-shadow:none',
 'shadow-none':'box-shadow:none','shadow-sm':'box-shadow:none','shadow-md':'box-shadow:none',
 'rounded':'border-radius:0.25rem','font-display':'','font-sans':'font-family:var(--ld-sans)','font-mono':'font-family:var(--ld-mono)',
 'font-bold':'font-weight:700','font-extrabold':'font-weight:800','font-semibold':'font-weight:600','font-medium':'font-weight:500','font-normal':'font-weight:400',
 'leading-none':'line-height:1','leading-tight':'line-height:1.25','leading-snug':'line-height:1.375','leading-normal':'line-height:1.5','leading-relaxed':'line-height:1.625','leading-loose':'line-height:2',
 'tracking-tighter':'letter-spacing:-0.05em','tracking-tight':'letter-spacing:-0.025em','tracking-normal':'letter-spacing:0','tracking-wide':'letter-spacing:0.025em','tracking-wider':'letter-spacing:0.05em',
 'outline-none':'outline:2px solid transparent;outline-offset:2px','appearance-none':'appearance:none',
 'grid-cols-1':'grid-template-columns:repeat(1,minmax(0,1fr))','grid-cols-2':'grid-template-columns:repeat(2,minmax(0,1fr))','grid-cols-3':'grid-template-columns:repeat(3,minmax(0,1fr))',
 'z-0':'z-index:0','z-10':'z-index:10','z-20':'z-index:20','z-30':'z-index:30','z-40':'z-index:40','z-50':'z-index:50',
 'inset-0':'inset:0','top-0':'top:0','bottom-0':'bottom:0','left-0':'left:0','right-0':'right:0',
 'opacity-0':'opacity:0','opacity-25':'opacity:.25','opacity-50':'opacity:.5','opacity-75':'opacity:.75','opacity-100':'opacity:1',
 'duration-100':'transition-duration:100ms','duration-150':'transition-duration:150ms','duration-200':'transition-duration:200ms','duration-300':'transition-duration:300ms','duration-500':'transition-duration:500ms','duration-700':'transition-duration:700ms','duration-1000':'transition-duration:1000ms',
 'ease-out':'transition-timing-function:cubic-bezier(0,0,.2,1)','ease-in':'transition-timing-function:cubic-bezier(.4,0,1,1)','ease-in-out':'transition-timing-function:cubic-bezier(.4,0,.2,1)',
 'border-0':'border-width:0','border':'border-width:1px','border-2':'border-width:2px',
 'border-t':'border-top-width:1px','border-b':'border-bottom-width:1px','border-l':'border-left-width:1px','border-r':'border-right-width:1px',
 'border-dashed':'border-style:dashed','border-solid':'border-style:solid',
 'rounded-sm':'border-radius:0.125rem','rounded-md':'border-radius:0.375rem','rounded-lg':'border-radius:0.5rem','rounded-xl':'border-radius:0.75rem','rounded-2xl':'border-radius:1rem','rounded-full':'border-radius:9999px','rounded-none':'border-radius:0',
 'ring-0':'box-shadow:none','ring-1':'box-shadow:0 0 0 1px #e2e8f0','ring-2':'box-shadow:0 0 0 2px #e2e8f0',
 'line-clamp-2':'display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden',
 'underline-offset-4':'text-underline-offset:4px','decoration-dotted':'text-decoration-style:dotted',
 'basis-full':'flex-basis:100%','min-h-screen':'min-height:100vh','min-w-0':'min-width:0',
 'w-full':'width:100%','h-full':'height:100%','mx-auto':'margin-left:auto;margin-right:auto','my-auto':'margin-top:auto;margin-bottom:auto','m-auto':'margin:auto',
}

MAXW = {'sm':'24rem','md':'28rem','lg':'32rem','xl':'36rem','2xl':'42rem','3xl':'48rem','4xl':'56rem','5xl':'64rem','7xl':'80rem','full':'100%','none':'none'}

def gen(tok):
    t = tok
    if t in SIMPLE: return SIMPLE[t] or None
    m = re.fullmatch(r'(bg|text|border|ring|accent|decoration)-([\w/.-]+)', t)
    if m:
        prop, val = m.group(1), m.group(2)
        col = color_val(val)
        if not col: return None
        return {'bg':'background-color','text':'color','border':'border-color','ring':'box-shadow','accent':'accent-color','decoration':'text-decoration-color'}[prop] + \
               (':'+col if prop!='ring' else ':0 0 0 3px '+col)
    m = re.fullmatch(r'text-(\w+)', t)
    if m and m.group(1) in FSZ: return f'font-size:{FSZ[m.group(1)]}'
    m = re.fullmatch(r'(p|px|py|pt|pb|pl|pr|m|mx|my|mt|mb|ml|mr)-([\w.-]+)', t)
    if m:
        prop, v = m.group(1), m.group(2)
        val = 'auto' if v == 'auto' else sp(v)
        if val is None: return None
        if prop in ('p','m'): return f'{"padding" if prop=="p" else "margin"}:{val}'
        axis_side = {'x':('left','right'),'y':('top','bottom'),'t':('top',),'b':('bottom',),'l':('left',),'r':('right',)}[prop[1]]
        base = 'padding' if prop[0]=='p' else 'margin'
        return ';'.join(f'{base}-{sd}:{val}' for sd in axis_side)
    m = re.fullmatch(r'gap-([\d.]+)', t)
    if m: return f'gap:{sp(m.group(1))}'
    m = re.fullmatch(r'gap-([xy])-([\d.]+)', t)
    if m: return f'{"column" if m.group(1)=="x" else "row"}-gap:{sp(m.group(2))}'
    m = re.fullmatch(r'w-([\w/%.-]+)', t)
    if m:
        v = m.group(1)
        if re.fullmatch(r'\d+/\d+', v): a,b=v.split('/'); return f'width:{round(int(a)/int(b)*100,4)}%'
        return f'width:{sp(v)}' if sp(v) else None
    m = re.fullmatch(r'h-([\w/%.-]+)', t)
    if m:
        v = m.group(1)
        if re.fullmatch(r'\d+/\d+', v): a,b=v.split('/'); return f'height:{round(int(a)/int(b)*100,4)}%'
        return f'height:{sp(v)}' if sp(v) else None
    m = re.fullmatch(r'max-w-(\w+)', t)
    if m and m.group(1) in MAXW: return f'max-width:{MAXW[m.group(1)]}'
    m = re.fullmatch(r'max-h-(\w+)', t)
    if m:
        v = '100%' if m.group(1)=='full' else sp(m.group(1))
        return f'max-height:{v}' if v else None
    m = re.fullmatch(r'-?(translate-[xy]-[\w/]+|-?rotate-\d+|scale-\d+)', t)
    if m:
        d = m.group(1)
        sign = '-' if t.startswith('-') else ''
        mm = re.fullmatch(r'translate-([xy])-([\w/%]+)', d)
        if mm:
            v = {'1/2':'50%','full':'100%'}.get(mm.group(2), sp(mm.group(2)))
            if v: return f'transform:translate{mm.group(1).upper()}({sign}{v})'
        mm = re.fullmatch(r'-?rotate-(\d+)', d)
        if mm: return f'transform:rotate({sign}{mm.group(1)}deg)'
        mm = re.fullmatch(r'scale-(\d+)', d)
        if mm: return f'transform:scale({int(mm.group(1))/100})'
    m = re.fullmatch(r'(top|bottom|left|right)-([\w/%.-]+)', t)
    if m:
        v = {'0':'0','1/2':'50%','full':'100%','auto':'auto'}.get(m.group(2)) or sp(m.group(2))
        return f'{m.group(1)}:{v}' if v else None
    m = re.fullmatch(r'(w|h|min-w|max-w|min-h|max-h)-\[([^\]]+)\]', t)
    if m:
        pm = {'w':'width','h':'height','min-w':'min-width','max-w':'max-width','min-h':'min-height','max-h':'max-height'}
        return f'{pm[m.group(1)]}:{m.group(2)}'
    return None

base_rules, special = [], []
for tok in sorted(tokens):
    if ':' in tok or tok.startswith('ld-') or tok in ('tone-chip','counter-reset','skeleton-block','accordion-panel','accordion-trigger','group-hover'):
        continue
    body = gen(tok)
    if body: base_rules.append(f'.{esc(tok)}{{{body}}}')

for tok in sorted(tokens):
    m = re.fullmatch(r'space-([yx])-([\d.]+)', tok)
    if m:
        axis = 'margin-top' if m.group(1)=='y' else 'margin-left'
        special.append(f'.{esc(tok)} > * + *{{{axis}:{sp(m.group(2))}}}')
    m = re.fullmatch(r'divide-y(-\d+)?', tok)
    if m: special.append(f'.{esc(tok)} > * + *{{border-top-width:1px}}')
    m = re.fullmatch(r'divide-x(-\d+)?', tok)
    if m: special.append(f'.{esc(tok)} > * + *{{border-left-width:1px}}')
    m = re.fullmatch(r'divide-([\w/]+)', tok)
    if m:
        c = color_val(m.group(1))
        if c: special.append(f'.{esc(tok)} > * + *{{border-color:{c}}}')

# hover/focus/active variants
hov = {}
for m in re.finditer(r'class="([^"]*)"', s):
    for t in m.group(1).split():
        mm = re.fullmatch(r'(hover|focus|active|focus-visible):(sm:)?([A-Za-z0-9:/.\[\]-]+)', t)
        if mm: hov.setdefault((mm.group(1), mm.group(2) or ''), set()).add(mm.group(3))
pseudo = {'hover':':hover','focus':':focus','active':':active','focus-visible':':focus-visible'}
hov_rules = []
for (var, sm), toks in sorted(hov.items()):
    inner = []
    for tok in sorted(toks):
        body = gen(tok)
        if body:
            cls = '.' + esc(((sm + ':') if sm else '') + var + ':' + tok)
            inner.append(cls + pseudo[var] + '{' + body + '}')
    if inner: hov_rules.extend(inner)

# responsive variants
resp = {}
for m in re.finditer(r'class="([^"]*)"', s):
    for t in m.group(1).split():
        mm = re.fullmatch(r'(sm|md|lg|xl):([A-Za-z0-9:/.\[\]-]+)', t)
        if mm: resp.setdefault(mm.group(1), set()).add(mm.group(2))
mq = {'sm':'640px','md':'768px','lg':'1024px','xl':'1280px'}
resp_blocks = []
for bp in ('sm','md','lg','xl'):
    if bp not in resp: continue
    inner = []
    for tok in sorted(resp[bp]):
        body = gen(tok)
        if body:
            b = body.replace('!important','') + ' !important'
            inner.append('.' + esc(bp + ':' + tok) + '{' + b + '}')
    if inner:
        resp_blocks.append(f'@media (min-width:{mq[bp]}){{\n' + '\n'.join(inner) + '\n}')

out = [
 '/* LetterDesk — css/utils.css : generated minimal utility layer (replaces the',
 '   Tailwind CDN). Regenerate with: python3 scripts/gen_utils_css.py',
 '   Only classes actually used by index.html / js are emitted. */',
 ':root{--ld-sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;--ld-mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}',
 '*,::before,::after{box-sizing:border-border}',
 'html{line-height:1.5;-webkit-text-size-adjust:100%;font-family:var(--ld-sans)}',
 'body{margin:0;line-height:1.5;font-family:inherit}',
 'h1,h2,h3,h4,h5,h6{font-size:inherit;font-weight:inherit;margin:0}',
 'p{margin:0}',
 'ul,ol{margin:0;padding:0}',
 'a{color:inherit;text-decoration:inherit}',
 'button,input,select,textarea{font-family:inherit;font-size:inherit;font-weight:inherit;line-height:inherit;color:inherit;margin:0}',
 'button{background-color:transparent;background-image:none}',
 'img,svg{display:block;vertical-align:middle;max-width:100%;height:auto}',
 'table{border-collapse:collapse}',
 '@keyframes spin{to{transform:rotate(360deg)}}',
 '@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}',
]
out += base_rules + special + hov_rules + resp_blocks
css = '\n'.join(out).replace('box-sizing:border-border', 'box-sizing:border-box')
open('/workspace/css/utils.css', 'w', encoding='utf-8').write(css + '\n')
print('wrote css/utils.css:', len(base_rules), 'base,', len(special), 'compound,',
      len(hov_rules), 'variants,', len(resp_blocks), 'media blocks;', len(css), 'bytes')

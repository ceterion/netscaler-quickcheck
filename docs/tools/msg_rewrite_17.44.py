import re,sys,json
SRC='/home/claude/repo/netscaler-quickcheck/docs/tools/ns_quickcheck_17.44_pre_catalog.sh'
MAP='/home/claude/repo/netscaler-quickcheck/docs/tools/msgmap_17.44.tsv'
CAT='/home/claude/repo/netscaler-quickcheck/ns_quickcheck.msg.de'
OUT='/home/claude/tools/rewritten.sh'
lines=open(SRC,encoding='utf-8').read().split('\n')
cat={}
for l in open(CAT,encoding='utf-8'):
    if l.startswith('#') or '\t' not in l: continue
    k,t=l.rstrip('\n').split('\t',1); cat[k]=t
rows=[]
for l in open(MAP,encoding='utf-8'):
    if l.startswith('#') or not l.strip(): continue
    f=l.rstrip('\n').split('\t'); rows.append((int(f[0]),f[1],f[2]))
SKIP_FUNC={'awk','perl','sed','printf','red','yel','org','tru','hdr'}
def dq_strings(line):
    """return list of (start,end) of top-level double-quoted strings' content (exclusive of quotes)"""
    res=[]; i=0; n=len(line); insq=False
    while i<n:
        c=line[i]
        if insq:
            if c=="'": insq=False
            i+=1; continue
        if c=="'": insq=True; i+=1; continue
        if c=='\\': i+=2; continue
        if c=='"':
            # scan to matching close
            j=i+1; depth=0; isq=False
            while j<n:
                d=line[j]
                if d=='\\': j+=2; continue
                if depth>0:
                    if isq:
                        if d=="'": isq=False
                    elif d=="'": isq=True
                    elif d=='(' : depth+=1
                    elif d==')': depth-=1
                    elif d=='"': pass
                    j+=1; continue
                if d=='$' and j+1<n and line[j+1]=='(': depth=1; j+=2; continue
                if d=='"': break
                j+=1
            res.append((i+1,j)); i=j+1; continue
        i+=1
    return res
def esc(seg): return seg.replace('\\','\\\\').replace('"','\\"').replace('$','\\$').replace('`','\\`')
def try_match(C,T):
    segs=re.split(r'%\d',T); nums=re.findall(r'%(\d)',T)
    if len(set(nums))!=len(nums): return None
    # candidates: segments possibly escaped
    variants=[segs,[esc(s) for s in segs],[s.replace('"','\\"') for s in segs],[s.replace('$','\\$') for s in segs]]
    for sv in variants:
        if sv[0]=='':
            start=0; cur=0
        else:
            start=C.find(sv[0]);
            if start<0: continue
            cur=start+len(sv[0])
        exprs=[]; ok=True
        for seg in sv[1:]:
            if seg=='':
                exprs.append(C[cur:]); cur=len(C)
            else:
                j=C.find(seg,cur)
                if j<0: ok=False; break
                exprs.append(C[cur:j]); cur=j+len(seg)
        if not ok: continue
        if len(exprs)!=len(nums): continue
        # order expressions by placeholder number
        byn={int(n):e for n,e in zip(nums,exprs)}
        ordered=[byn[i] for i in range(1,len(nums)+1)] if set(byn)==set(range(1,len(nums)+1)) else None
        if ordered is None: continue
        if any(e.strip()=='' for e in ordered): continue
        return (start,cur,ordered)
    return None
fails=[]; done=0; log=[]
bykey={}
for L,func,key in rows: bykey.setdefault(L,[]).append((func,key))
def locate(L,T,func):
    # msgmap lines refer to 17.43; find nearest line (within +-30) whose dq string matches T
    segs=[x for x in re.split(r'%\d',T) if x]
    if not segs: return None
    best=None
    for idx in range(max(0,L-1-30),min(len(lines),L-1+40)):
        ln=lines[idx]
        if all(seg in ln or esc(seg) in ln or seg.replace('"','\\"') in ln for seg in segs):
            if best is None or abs(idx-(L-1+4))<abs(best-(L-1+4)): best=idx
    return best
rowlist=[(L,func,key) for L in sorted(bykey) for func,key in bykey[L]]
pending={}
for L in sorted(bykey):
    group=bykey[L]; anchor=None
    for func,key in group:
        if func.startswith('out[TAG') or func in SKIP_FUNC: continue
        T=cat.get(key)
        if T is None: continue
        idx=locate(L,T,func)
        if idx is not None: anchor=idx; break
    for func,key in group:
        T=cat.get(key)
        if T is None: fails.append((L,func,key,'no-cat')); continue
        if func in SKIP_FUNC: fails.append((L,func,key,'skip-manual')); continue
        idx=anchor if (func.startswith('out[TAG') or anchor is not None) else None
        if idx is None: idx=locate(L,T,func)
        if idx is None: fails.append((L,func,key,'no-line')); continue
        pending.setdefault(idx,[]).append((func,key))
for idx in sorted(pending):
    L=idx+1; line=lines[idx]; orig=line
    for func,key in pending[idx]:
        T=cat.get(key)
        tagkeys=[]
        if key.startswith('TAG_'): tagkeys=[key]
        if func.startswith('out[TAG_'): tagkeys=[func[4:-1]]
        for tk in tagkeys:
            tt=cat[tk]; lit='  '+tt.ljust(8) if len(tt)<8 else '  '+tt+' '
            if lit in line: line=line.replace(lit,'$(tagf '+tk+')',1); done+=1
            elif '$(tagf '+tk+')' in line: pass
            else: fails.append((L,func,key,'tag-literal-missing'))
        if key.startswith('TAG_'): continue
        placed=False
        for (a,b) in dq_strings(line):
            C=line[a:b]; r=try_match(C,T)
            if r:
                s_,e_,ex=r
                if len(ex)==0: new='$(msg '+key+')'
                else: new='$(msg '+key+' '+' '.join('"'+x+'"' for x in ex)+')'
                line=line[:a]+C[:s_]+new+C[e_:]+line[b:]; placed=True; done+=1; break
        if not placed: fails.append((L,func,key,'no-match'))
    if line!=orig: lines[L-1]=line; log.append((L,orig,line))
open(OUT,'w',encoding='utf-8').write('\n'.join(lines))
print('done',done,'fails',len(fails))
json.dump({'fails':fails,'log':log},open('/home/claude/tools/rewrite_log.json','w'),ensure_ascii=False,indent=1)
from collections import Counter
print(Counter(f[3] for f in fails))

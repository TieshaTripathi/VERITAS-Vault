"""Small, dependency-free command-center components for Streamlit."""

import base64
import io
import math
import struct
import wave
from functools import lru_cache
from html import escape

import streamlit as st


def sparkline(values, color="#00f0ff"):
    """Render actual session samples; never invent a telemetry history."""
    samples = list(values)[-24:]
    if not samples:
        return '<div class="sparkline-empty">AWAITING FIRST SAMPLE</div>'
    low, high = min(samples), max(samples)
    points = " ".join(
        f"{i * 160 / max(1, len(samples) - 1):.1f},{29 - (v - low) / (high - low or 1) * 22:.1f}"
        for i, v in enumerate(samples)
    )
    return (
        '<svg class="micro-sparkline" viewBox="0 0 164 36" role="img" '
        'aria-label="Recent session samples">'
        f'<polyline points="{points}" fill="none" stroke="{color}" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<circle cx="{(len(samples)-1)*160/max(1,len(samples)-1):.1f}" '
        f'cy="{29-(samples[-1]-low)/(high-low or 1)*22:.1f}" r="3" fill="{color}"/></svg>'
    )


@lru_cache(maxsize=2)
def sound_data(kind):
    """Synthesize short PCM WAV cues locally, with no remote audio dependency."""
    notes = [(660, .11), (880, .11), (1320, .23)] if kind == "granted" else [
        (880, .14), (0, .07), (880, .14), (0, .07), (660, .24)
    ]
    rate = 22050
    pcm = bytearray()
    for freq, duration in notes:
        count = int(rate * duration)
        for index in range(count):
            envelope = min(1, index / (rate * .012), (count - index) / (rate * .025))
            value = .22 * envelope * math.sin(2 * math.pi * freq * index / rate)
            pcm.extend(struct.pack("<h", int(32767 * value)))
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        wav.writeframes(pcm)
    return "data:audio/wav;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


_audio = st.components.v2.component(
    "vault_audio",
    html='<audio preload="auto"></audio><button hidden type="button">Enable alert audio</button>',
    css="""button {background:#111d2e;color:#00f0ff;border:1px solid #00f0ff;
    border-radius:6px;padding:7px 12px;cursor:pointer;font:12px monospace;}""",
    js="""export default function({parentElement, data}) {
      const audio = parentElement.querySelector('audio');
      const button = parentElement.querySelector('button');
      if (!data.enabled || !data.event) {audio.pause(); button.hidden=true; return;}
      // DOM-local event identity survives unrelated Streamlit reruns.
      if (audio.dataset.event === data.event) return;
      audio.dataset.event = data.event;
      audio.src = data.src;
      audio.autoplay = true;
      const play = () => audio.play().then(() => {button.hidden=true;})
        .catch(() => {button.hidden=false;});
      button.onclick = play;
      play();
      return () => {audio.pause(); button.onclick=null;};
    }""",
)


def play_sound(kind, event, enabled=True):
    _audio(data={"src": sound_data(kind) if kind else "", "event": event,
                 "enabled": enabled}, key="verdict_audio")


_timer = st.components.v2.component(
    "vault_countdown",
    html="""<section class="timer">
      <div class="dial" role="timer" aria-label="Dual-custody time remaining">
        <svg viewBox="0 0 120 120" aria-hidden="true">
          <circle class="track" cx="60" cy="60" r="50"/>
          <circle class="arc" cx="60" cy="60" r="50"/>
        </svg><div class="readout"><strong></strong><small>/ 5.0 SEC</small></div>
      </div><div class="meta"><span>DUAL-CUSTODY WINDOW</span><h3></h3><p></p>
      <div class="legend"><i></i> SERVER-ANCHORED DEADLINE</div></div>
    </section>""",
    css="""
      .timer {display:flex;align-items:center;gap:18px;padding:18px;
        background:linear-gradient(120deg,#102034cc,#0a1423ee);border:1px solid #21364b;
        border-radius:14px;color:#e2e8f0;font-family:monospace;box-sizing:border-box;}
      .dial {position:relative;width:122px;min-width:100px;flex-shrink:0;}
      svg {display:block;width:100%;transform:rotate(-90deg);overflow:visible;}
      circle {fill:none;stroke-width:5;}.track{stroke:#203045;}
      .arc {stroke:#00f0ff;stroke-linecap:round;stroke-dasharray:314.159;
        transition:stroke .3s;filter:drop-shadow(0 0 4px currentColor);}
      .readout {position:absolute;inset:0;display:flex;flex-direction:column;
        align-items:center;justify-content:center;}.readout strong{font-size:28px;}
      small {font-size:9px;color:#91a6bd;margin-top:3px;}
      .meta span {font-size:9px;letter-spacing:1.4px;color:#91a6bd;}
      h3 {font-size:16px;margin:10px 0;}p{font:12px/1.6 sans-serif;color:#a5b6cb;margin:0;}
      .legend{font-size:8px;color:#91a6bd;margin-top:14px;letter-spacing:.6px;}
      i{display:inline-block;width:5px;height:5px;background:#00f0ff;border-radius:50%;margin-right:5px;}
      @media(max-width:360px){.timer{gap:12px;padding:12px;}.dial{width:104px;}}
      @media(prefers-reduced-motion:reduce){.arc{transition:none;}}
    """,
    js="""export default function({parentElement, data}) {
      const arc=parentElement.querySelector('.arc');
      const dial=parentElement.querySelector('.dial');
      const value=parentElement.querySelector('strong');
      const title=parentElement.querySelector('h3');
      const caption=parentElement.querySelector('p');
      // Subtract elapsed time from this server-provided budget. No browser clock skew.
      const end=performance.now()+data.remaining*1000;
      const tick=()=>{
        const remaining=data.state==='WAITING'?Math.max(0,(end-performance.now())/1000):data.remaining;
        const color=data.state==='BREACH'?'#ef4444':data.state==='STANDBY'?'#00f0ff':
          data.state==='GRANTED'?'#10b981':remaining>3?'#10b981':remaining>1.5?'#f59e0b':'#ef4444';
        arc.style.stroke=color;arc.style.color=color;
        arc.style.strokeDashoffset=314.159*(1-(data.state==='GRANTED'?1:remaining/5));
        value.textContent=data.state==='GRANTED'?'PASS':remaining.toFixed(1)+'s';
        value.style.color=color;dial.setAttribute('aria-label',value.textContent+' remaining');
        title.textContent=data.state==='WAITING'?(remaining>0?'Awaiting party 2':'Window expired'):
          data.state==='GRANTED'?'Custody verified':data.state==='BREACH'?'Access rejected':'Ready to verify';
        caption.textContent=data.state==='WAITING'?'Verify the second distinct party before the window closes.':
          data.state==='GRANTED'?'Both identities satisfied the access policy.':
          data.state==='BREACH'?'Vault remains locked. Review the event below.':'The first verified party starts the clock.';
      };
      tick();const interval=setInterval(tick,50);return()=>clearInterval(interval);
    }""",
)


def countdown(state, remaining):
    _timer(data={"state": state, "remaining": max(0, min(5, remaining))}, key="custody_timer")


_ledger = st.components.v2.component(
    "vault_ledger",
    html='<div class="scroll"><table><thead><tr><th>TIME / LOCAL</th><th>ACCESS PROTOCOL</th><th>VERIFIED PARTIES</th><th>VERDICT</th><th>SHA-256 DIGEST ↗</th><th>STORAGE</th></tr></thead><tbody></tbody></table></div><p class="feedback" role="status"></p>',
    css="""
      .scroll{overflow:auto;border:1px solid #22354a;border-radius:12px;max-height:400px;}
      table{width:100%;border-collapse:collapse;text-align:left;font:12px/1.5 sans-serif;color:#c2d1e2;background:#0b1523;}
      th{position:sticky;top:0;background:#101f30;color:#8da7bf;font:9px monospace;letter-spacing:1px;white-space:nowrap;padding:16px;}
      td{padding:14px 16px;border-top:1px solid #1b2b3c;max-width:240px;overflow-wrap:anywhere;}
      tbody tr{transition:background .2s;}tbody tr:hover,tbody tr:focus-within{background:#00f0ff0c;}
      .badge{display:inline-block;padding:4px 8px;border:1px solid currentColor;border-radius:5px;font:10px monospace;}
      .granted{color:#34d399;background:#10b98118;}.breach{color:#fb7185;background:#ef444418;}
      .waiting{color:#fbbf24;background:#f59e0b18;}.neutral{color:#91a6bd;}
      button{color:#67e8f9;border:1px solid #28505c;background:#0e2835;border-radius:5px;
        padding:6px 9px;font:11px monospace;cursor:pointer;white-space:nowrap;}
      button:hover{background:#144453;}button:focus-visible{outline:2px solid #00f0ff;outline-offset:3px;}
      .feedback{color:#a5b6cb;font:12px sans-serif;margin:8px 2px;min-height:15px;}
      @media(prefers-reduced-motion:reduce){tbody tr{transition:none;}}
    """,
    js="""export default function({parentElement,data,setTriggerValue}) {
      const body=parentElement.querySelector('tbody');body.replaceChildren();
      const feedback=parentElement.querySelector('.feedback');
      data.forEach(row=>{
        const tr=document.createElement('tr');
        const cell=(text)=>{const td=document.createElement('td');td.textContent=text||'—';tr.appendChild(td);return td;};
        cell((row.timestamp||'').slice(0,19));cell(row.mode);cell(row.verified_parties);
        const verdict=String(row.verdict||'');
        const status=verdict.includes('GRANTED')?'GRANTED':/BREACH|DENIED/.test(verdict)?'BREACH':verdict.includes('WAITING')?'WAITING':verdict;
        const badge=document.createElement('span');badge.className='badge '+({GRANTED:'granted',BREACH:'breach',WAITING:'waiting'}[status]||'neutral');
        badge.textContent=status;badge.title=verdict;const verdictCell=cell('');verdictCell.replaceChildren(badge);
        const hash=String(row.sha256_hash||'');const hashCell=cell('');
        if(hash){const button=document.createElement('button');button.type='button';
          button.textContent=hash.slice(0,10)+'…'+hash.slice(-6)+' ⧉';button.title='Copy SHA-256: '+hash;
          button.setAttribute('aria-label','Copy SHA-256 digest '+hash);
          button.onclick=async()=>{try{await navigator.clipboard.writeText(hash);
            feedback.textContent='Digest copied to clipboard.';setTriggerValue('copied',hash);
          }catch(error){feedback.textContent='Clipboard access is blocked. Select and copy the digest below.';
            const manual=document.createElement('input');manual.value=hash;manual.readOnly=true;
            manual.setAttribute('aria-label','SHA-256 digest for manual copy');hashCell.appendChild(manual);manual.select();}};
          hashCell.replaceChildren(button);}
        cell(row.status);body.appendChild(tr);
      });
    }""",
)


def audit_ledger(rows):
    result = _ledger(data=rows, key="audit_ledger", on_copied_change=lambda: None)
    if result.copied:
        st.toast("Copied SHA-256 Digest!")


def metric_tile(label, value, note, history, color="#00f0ff", index="01"):
    return (
        f'<div class="metric-card"><div class="metric-top"><span>{escape(label)}</span>'
        f'<span class="metric-index">{index}</span></div>'
        f'<div class="metric-num" style="color:{color}">{escape(str(value))}</div>'
        f'{sparkline(history, color)}<div class="metric-note">{escape(note)}</div></div>'
    )

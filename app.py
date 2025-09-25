import os
async def send_resend_email(matches, recipients):
if not matches or not recipients: return
html = f"<h2>EMMA Daily Digest — {len(matches)} matches</h2><ul>"
for m in matches:
html += f"<li><a href='{m['url']}'>{m['title']}</a> — matched_terms: {', '.join(m.get('matched_terms',[]))}</li>"
html += '</ul>'


payload = {
'from': FROM_EMAIL,
'to': recipients,
'subject': f'EMMA Daily Digest: {len(matches)} matches',
'html': html
}
headers = {'Authorization': f'Bearer {RESEND_API_KEY}','Content-Type':'application/json'}
try:
r = await asyncio.to_thread(requests.post, 'https://api.resend.com/emails', json=payload, headers=headers, timeout=30)
r.raise_for_status()
except Exception as e:
print('Resend send failed:', e)


# --- FastAPI ---
app = FastAPI()
templates = Jinja2Templates(directory='templates')


@app.get('/', response_class=HTMLResponse)
async def home(request: Request):
recent = await get_recent_matches(days=7)
return templates.TemplateResponse('index.html', {'request':request,'matches':recent,'query':None})


@app.post('/search', response_class=HTMLResponse)
async def search(request: Request, query: str = Form(...)):
recent = await get_recent_matches(days=30)
matches = [r for r in recent if match_text(r.title, query) or (r.matched_terms and any(match_text(t, query) for t in r.matched_terms))]
return templates.TemplateResponse('index.html', {'request':request,'matches':matches,'query':query})


@app.get('/healthz')
def healthz():
return {'status':'ok'}


# --- Scheduler ---
scheduler = AsyncIOScheduler()
scheduler.add_job(lambda: asyncio.create_task(daily_job()), 'interval', days=1, next_run_time=None)
scheduler.start()


async def daily_job():
print('Running daily EMMA scan —', datetime.utcnow().isoformat())
matches = await scan_once()
if matches and RESEND_API_KEY and FROM_EMAIL and ALERT_EMAILS:
await send_resend_email(matches, ALERT_EMAILS)
deleted = await cleanup_old(RETENTION_DAYS)
print('Cleanup removed rows:', deleted)


# --- Startup ---
@app.on_event('startup')
async def startup():
await init_db()
if RUN_INITIAL_SCAN:
await daily_job()


# --- Local run ---
if __name__ == '__main__':
import uvicorn
uvicorn.run('app:app', host='0.0.0.0', port=int(os.getenv('PORT',8000)), reload=True)

# app.py — single-file EMMA Monitor
continue


text_to_search = title or ''
matched = False
matched_terms = []


# If configured, fetch document body to search inside documents too
if FETCH_DOCS_ON_SCAN:
doc_text = fetch_url_text(link)
text_to_search = (title or '') + '\n\n' + (doc_text or '')


# Evaluate DAILY_QUERIES from env if provided
daily_queries_json = os.getenv('DAILY_QUERIES_JSON')
if daily_queries_json:
try:
daily_queries = json.loads(daily_queries_json)
except Exception:
daily_queries = []


for q in daily_queries:
if match_text(text_to_search, q):
matched = True
matched_terms.append(q)


# Insert metadata; we always save the row so the front end can search later.
insert_metadata(title, link, matched=matched, matched_terms=matched_terms)


if matched:
matches.append({
'title': title,
'url': link,
'matched_terms': matched_terms,
})


SEEN_URLS.add(link)


return matches


# --- Scheduler ---


scheduler = BackgroundScheduler()




def daily_job():
print('Daily scan started', datetime.utcnow().isoformat())
matches = scan_once()


# Send digest for matches
if matches and RESEND_API_KEY and FROM_EMAIL and ALERT_EMAILS:
send_resend_email(matches, ALERT_EMAILS)


deleted = cleanup_old(RETENTION_DAYS)
print('Cleanup deleted rows:', deleted)




# set to run once every 24 hours
scheduler.add_job(daily_job, 'interval', days=1, next_run_time=None)
scheduler.start()
# ensure scheduler is shut down on exit
atexit.register(lambda: scheduler.shutdown())


# Optionally run initial scan on startup
if RUN_INITIAL_SCAN:
try:
# small delay to let env/DB come up on some platforms
time.sleep(1)
init_db()
daily_job()
except Exception as e:
print('Initial scan failed:', e)
else:
init_db()


# --- FastAPI app ---
app = FastAPI()




@app.get('/', response_class=HTMLResponse)
def home(request: Request):
recent = get_recent_matches(days=7)
return templates.TemplateResponse('index.html', {"request": request, "matches": recent, "query": None})




@app.post('/search', response_class=HTMLResponse)
def search(request: Request, query: str = Form(...)):
# search metadata in DB (title + matched_terms); optionally re-fetch documen

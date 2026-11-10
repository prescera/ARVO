import requests
# obsolete url format: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=30419
import re
from datetime import datetime
from .utils_log import *
from .utils import *
import json
from google.cloud import storage
from urllib.parse import urlparse
from urllib.parse import parse_qs
import hashlib 
if NEW_ISSUE_TRACKER:
    META = ARVO / NEW_ISSUE_TRACKER
def metaFilter():
    localIds = getAllLocalIds()[::-1]
    res = []
    # nonC = []
    broken_srcmaps = []
    false_positives = []
    for localId in localIds:
        target_dir = Path(DATADIR)/"Issues"/(str(localId)+"_files")
        if not target_dir.exists() or len(list(target_dir.iterdir())) <2:
            res.append(localId)
            WARN(f"[!] Have less than 2 srcmaps, deleting issue {localId}...")
            continue
        srcmap = getSrcmaps(localId)
        # Filter out Borken srcmap
        out = False
        for x in srcmap:
            with open(x) as f:
                data = json.loads(f.read())
            for key in data.keys():
                item = data[key]
                values = list(item.values())
                if "unknown" in values or "UNKNOWN" in values:
                    broken_srcmaps.append(localId)
                    out = True
                    break
            if out == True:
                break

        # Filter out the false positive cases:
        tmp_lst = []
        for y in srcmap:
            file_hash = hashlib.md5()
            with open(y,'rb') as f:
                file_hash.update(f.read())
            tmp_lst.append(file_hash.digest())
        if len(set(tmp_lst)) != len(tmp_lst):
            false_positives.append(localId)
    res.extend(broken_srcmaps)
    # print(false_positives)
    # res.extend(false_positives)
    res = list(set(res))
    remove_issue_meta(res)
    remove_issue_data(res)
def _month_windows(since, until):
    # Yield [start, end) date pairs, one per calendar month, covering [since, until)
    cur = since.replace(day=1)
    while cur < until:
        nxt = cur.replace(year=cur.year + 1, month=1) if cur.month == 12 else cur.replace(month=cur.month + 1)
        yield max(cur, since), min(nxt, until)
        cur = nxt
def getIssueIds(since=None, until=None):
    # since/until: datetime.date; defaults cover the whole tracker history (2016 -> now)
    since = since or datetime(2016, 1, 1).date()
    until = until or (datetime.now().date().replace(month=12, day=31))
    localIds = []
    session = requests.Session()
    # Step 1: Get the token from the cookie
    session.get("https://issues.oss-fuzz.com/", timeout=60)
    xsrf_token = session.cookies.get("XSRF_TOKEN")
    # Step 2: Use it in the header
    headers = {
        'Content-Type': 'application/json',
        'Origin': 'https://issues.oss-fuzz.com',
        'Referer': 'https://issues.oss-fuzz.com/',
        'X-XSRF-Token': xsrf_token
    }
    url = 'https://issues.oss-fuzz.com/action/issues/list'
    # Query month by month: the tracker caps a single query at 2,500 results
    for start, end in _month_windows(since, until):
        init_num = len(localIds)
        start_index = 0
        while True:
            query = f"type:vulnerability status:verified created>={start.isoformat()} created<{end.isoformat()}"
            data = [None, None, None, None, None, ["391"], [query, None, 500, f"start_index:{start_index}"]]
            response = session.post(url, headers=headers, json=data, timeout=120)
            data = response.text
            # Fix malformed JSON-like string
            clean_data = re.sub(r'\bnull\b', 'null', data)
            clean_data = clean_data.replace("'", '"')
            clean_data = re.sub(r',\s*]', ']', clean_data)
            # Parse with regex (quick and dirty)
            issues = re.findall(r'\[\s*null\s*,\s*(\d+),\s*\[\d+,\d+,\d+,\d+,\d+,"(.*?)"', clean_data)

            for issue_id, title in issues:
                localIds.append(issue_id)
            if len(issues)!=500:
                break
            start_index+=500
            if (len(localIds) - init_num == 2500):
                PANIC(f"Query limit (2,500) hit for {start}..{end}; results would be truncated")
        added_num = len(localIds) - init_num
        SUCCESS(f"[+] Added {added_num:,} issues from {start}..{end} ({len(localIds):,} total)")

    return list(dict.fromkeys(int(x) for x in localIds))

def parse_oss_fuzz_report(report_text: bytes,localId: int) -> dict:
    text = report_text.decode('unicode_escape', errors='ignore')  # decode escaped unicode like \u003d
    def extract(pattern,default=''):
        m = re.search(pattern, text)
        if not m:
            if default=='':
                raise ValueError(f"FAILED to PARSE {pattern} {localId=}")
            else:
                return default
        return m.group(1).strip()
    res = {
        "project": extract(r'(?:Target|Project):\s*(\S+)','NOTFOUND'),
        "job_type": extract(r'Job Type:\s*(\S+)'),
        "platform": extract(r'Platform Id:\s*(\S+)','linux'),
        "crash_type": extract(r'Crash Type:\s*(.+)'),
        "crash_address": extract(r'Crash Address:\s*(\S+)'),
        "severity": extract(r'Security Severity:\s*(\w+)', 'Medium'),
        "regressed": extract(r'(?:Regressed|Crash Revision):\s*(https?://\S+)',"NO_REGRESS"),
        "reproducer": extract(r'(?:Minimized Testcase|Reproducer Testcase|Download).*:\s*(https?://\S+)'),
        "verified_fixed": extract(r'(?:fixed in|Fixed:)\s*(https?://\S+revisions\S+)','NO_FIX'),
        "localId": localId
    }
    sanitizer_map = {
        "address (ASAN)": "address",
        "memory (MSAN)": "memory",
        "undefined (UBSAN)": "undefined",
        "asan": "address",
        "msan": "memory",
        "ubsan": "undefined",
    }
    fuzz_target = extract(r'(?:Fuzz Target|Fuzz target|Fuzz target binary|Fuzzer):\s*(\S+)','NOTFOUND')
    job_parts = res['job_type'].split("_")
    if len(job_parts)==2 or job_parts[1] not in sanitizer_map:
        WARN(f"FAILED to GET sanitizer {localId=} {res['job_type']}")
        return False
    else:
        res['sanitizer'] = sanitizer_map[job_parts[1]]

    if fuzz_target != 'NOTFOUND':
        res['fuzz_target'] = fuzz_target
    if res['project'] == "NOTFOUND":
        res['project'] = res['job_type'].split("_")[-1]
    return res
def meta_getIssue(issue_id):
    # The tracker no longer serves /action/issues/{id}/events. The report text (job type,
    # crash, regressed range, testcase) is in the issue itself, and the
    # "verified as fixed in <range>" comment comes from POST .../updates.
    base = f'https://issues.oss-fuzz.com/action/issues/{issue_id}'
    session = requests.Session()
    # Step 1: Get the token from the cookie (currently unset by the tracker; reads work without it)
    try:
        session.get("https://issues.oss-fuzz.com/", timeout=60)
    except requests.RequestException:
        pass
    xsrf_token = session.cookies.get("XSRF_TOKEN") or ''
    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en,zh-CN;q=0.9,zh;q=0.8,ar;q=0.7',
        'priority': 'u=1, i',
        'referer': 'https://issues.oss-fuzz.com/',
        'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Linux"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
        'X-XSRF-Token': xsrf_token
    }
    try:
        issue = session.get(base, headers=headers, timeout=60)
        updates = session.post(f'{base}/updates?currentTrackerId=391', json=[issue_id],
            headers={**headers, 'content-type': 'application/json', 'origin': 'https://issues.oss-fuzz.com'}, timeout=60)
        if issue.status_code != 200 or updates.status_code != 200:
            WARN(f"FAIL on {issue_id} (HTTP {issue.status_code}/{updates.status_code}), skip")
            return False
        res = parse_oss_fuzz_report(issue.content + b"\n" + updates.content, issue_id)
    except Exception as e:
        WARN(f"FAIL on {issue_id}: {e}, skip")
        return False
    return res
def meta_getIssues(issue_ids, workers=16):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    issues = []
    if not MetaDataFile.exists():
        MetaDataFile.touch()
    done = []
    with open(MetaDataFile,'r') as f:
        lines = f.readlines()
    for line in lines:
        done.append(json.loads(line)['localId'])
    todo = [x for x in issue_ids if x not in done]
    INFO(f"Added {len(todo)} new issues")
    # Fetch in parallel; only this thread appends to MetaDataFile
    with ThreadPoolExecutor(workers) as pool, open(MetaDataFile,'a') as f:
        futures = {pool.submit(meta_getIssue, x): x for x in todo}
        for fut in bar(as_completed(futures)):
            res = fut.result()
            if res:
                issues.append(res)
                f.write(json.dumps(res) + '\n')
                f.flush()
            else:
                WARN(f"Failed to fetch the issue for {futures[fut]}")
    return todo
# Parse the job type into parts
def parse_job_type(job_type):
    parts = job_type.split('_')
    remainder = []
    parsed = {}
    while len(parts) > 0:
        part = parts.pop(0)
        if part in ['afl', 'honggfuzz', 'libfuzzer']:
            parsed['engine'] = part
        elif part in ['asan', 'ubsan', 'msan']:
            parsed['sanitizer'] = part
        elif part == 'i386':
            parsed['arch'] = part
        elif part == 'untrusted':
            parsed['untrusted'] = True
        else:
            remainder.append(part)
    if len(remainder) > 0:
        parsed['project'] = '_'.join(remainder)
    if 'arch' not in parsed:
        parsed['arch'] = 'x86_64'
    if 'engine' not in parsed:
        parsed['engine'] = 'none'
    if 'untrusted' not in parsed:
        parsed['untrusted'] = False
    return parsed
storage_client = None
def download_build_artifacts(metadata, url, outdir):
    global storage_client
    if storage_client is None:
        # clusterfuzz-builds* buckets are public; fall back to anonymous access without a key
        try:
            storage_client = storage.Client()
        except Exception:
            storage_client = storage.Client.create_anonymous_client()
    bucket_map = {
        "libfuzzer_address_i386": "clusterfuzz-builds-i386",
        "libfuzzer_memory_i386": "clusterfuzz-builds-i386",
        "libfuzzer_undefined_i386": "clusterfuzz-builds-i386",
        "libfuzzer_address": "clusterfuzz-builds",
        "libfuzzer_memory": "clusterfuzz-builds",
        "libfuzzer_undefined": "clusterfuzz-builds",
        "afl_address": "clusterfuzz-builds-afl",
        "honggfuzz_address": "clusterfuzz-builds-honggfuzz",
    }
    sanitizer_map = {
        "address (ASAN)": "address",
        "memory (MSAN)": "memory",
        "undefined (UBSAN)": "undefined",
        "asan": "address",
        "msan": "memory",
        "ubsan": "undefined",
        "address": "address",
        "memory": "memory",
        "undefined": "undefined",
        None: "",
    }
    job_name = metadata["job_type"]
    job = parse_job_type(job_name)
    
    # These don't have any build artifacts
    if job['untrusted']: return False
    if job['engine'] == 'none': return False
    # Prefer the info from the job name, since the metadata
    # format has changed several times.
    if 'project' in metadata:
        project = metadata["project"]
    else:
        project = job['project']
    if 'sanitizer' in metadata:
        sanitizer = sanitizer_map[metadata["sanitizer"]]
        assert sanitizer == sanitizer_map[job['sanitizer']]
    else:
        sanitizer = sanitizer_map[job['sanitizer']]
    fuzzer = job['engine']
    bucket_string = f"{fuzzer}_{sanitizer}"
    if job['arch'] == 'i386':
        bucket_string += '_i386'
    assert bucket_string in bucket_map
    bucket_name = bucket_map[bucket_string]

    # Grab the revision from the URL
    urlparams = parse_qs(urlparse(url).query)
    
    if 'revision' in urlparams:
        revision = urlparams['revision'][0]
    elif 'range' in urlparams:
        revision = urlparams['range'][0].split(':')[1]
    else:
        return False
    
    zip_name = f'{project}-{sanitizer}-{revision}.zip'
    srcmap_name = f'{project}-{sanitizer}-{revision}.srcmap.json'
    zip_path = f'{project}/{zip_name}'
    srcmap_path = f'{project}/{srcmap_name}'
    downloaded_files = []
    bucket = storage_client.bucket(bucket_name)
    for path, name in [(srcmap_path, srcmap_name)]:
#    for path, name in [(zip_path, zip_name), (srcmap_path, srcmap_name)]:

        download_path = outdir / name

        if download_path.exists():
            print(f'Skipping {name} (already exists)')
            downloaded_files.append(download_path)
            continue
        blob = bucket.blob(path)
        if not blob.exists():
            print(f'Skipping {name} (not found)')
            continue
        print(download_path)
        blob.download_to_filename(str(download_path))
        
        print(f'Downloaded {name}')
        downloaded_files.append(download_path)
    return [str(f) for f in downloaded_files]
def _projectLanguage(pname):
    # getLanguage() needs the srcmaps, which are not downloaded yet at this stage,
    # so resolve the language from the project name (PLanguage.json, then project.yaml).
    if pname in PLanguage: return PLanguage[pname]
    url = f"https://raw.githubusercontent.com/google/oss-fuzz/master/projects/{pname}/project.yaml"
    try:
        r = requests.get(url, timeout=30)
        m = re.search(r'^language\s*:\s*"?([^\s"]+)', r.text, re.M) if r.status_code == 200 else None
    except requests.RequestException:
        m = None
    PLanguage[pname] = m.group(1) if m else None
    return PLanguage[pname]
def data_download(localIds = None):
    metadata = {}
    for line in open(MetaDataFile):
        line = json.loads(line)
        if localIds == None or line['localId'] in localIds:
            metadata[line['localId']] = line
    def _one(localId):
        # Returns True if the issue should be removed from the dataset
        issue_dir = META / "Issues" / f"{localId}_files"
        if issue_dir.exists():
            done = []
            for x in issue_dir.iterdir():
                done.append(x)
            if len(done) == 2:
                return False
            elif len(done) != 0:
                shutil.rmtree(issue_dir)
        issue_dir.mkdir(parents=True, exist_ok=True)
        if 'regressed' not in metadata[localId] or 'verified_fixed' not in metadata[localId] or \
            metadata[localId]['verified_fixed'] == 'NO_FIX':
            return False
        if _projectLanguage(metadata[localId]['project']) not in ['c','c++']:
            WARN(f"[!] Not C/C++ Issue: {localId=}")
            return True
        # Not silentRun(): it swaps the global sys.stdout, which is unsafe across threads
        for rng in ('regressed', 'verified_fixed'):
            try:
                ok = download_build_artifacts(metadata[localId], metadata[localId][rng], issue_dir)
            except Exception as e:
                ok = False
            if not ok:
                WARN(f"[!] Failed to download the srcmap: {localId=}")
                return True
        return False
    from concurrent.futures import ThreadPoolExecutor
    global storage_client
    if storage_client is None:   # initialise once, before the threads race on it
        try:
            storage_client = storage.Client()
        except Exception:
            storage_client = storage.Client.create_anonymous_client()
    with ThreadPoolExecutor(16) as pool:
        ids = list(metadata)
        to_remove = [i for i, rm in zip(ids, bar(pool.map(_one, ids))) if rm]

    remove_issue_meta(to_remove)
    remove_issue_data(to_remove)
    return True
def getMeta(since=None, until=None):
    if not NEW_ISSUE_TRACKER: PANIC("THIS SCRIPT ONLY WORKS FOR NEW_ISSUE_TRACKER")
    if not META.exists(): META.mkdir(parents=True)
    todo = meta_getIssues(getIssueIds(since, until))
    print(todo)
    data_download()  # all issues: resumes srcmap downloads from interrupted runs; finished ones are skipped

if __name__ == "__main__":
    pass

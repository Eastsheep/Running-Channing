"""每天從 Garmin Connect 抓跑步紀錄，加密後寫入 data/runs.enc.json；
每次跑步的逐公里分段與曲線另外加密寫入 data/detail/（一次跑步一個檔，不含 GPS 位置）。

需要的環境變數（存在 GitHub Secrets）：
  GARMIN_EMAIL, GARMIN_PASSWORD  Garmin 帳號密碼
  DATA_PASSWORD                  儀表板解鎖用的密碼，用來加密資料
  DEEPSEEK_API_KEY（選用）        有設定就會在資料更新時產生 AI 教練分析
"""
import base64
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

OUT = os.path.join(os.path.dirname(__file__), "..", "data", "runs.enc.json")
DETAIL_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "detail")
DETAIL_RUNS = 100  # 第一次同步時往回抓明細的跑步次數
DETAIL_POINTS = 160  # 每次跑步的曲線點數
ITERATIONS = 250_000
PAGE = 200
MAX_ACTIVITIES = 5000


def is_run(a):
    t = (a.get("activityType") or {}).get("typeKey", "")
    return "run" in t


def num(v, scale=1.0, digits=None):
    if v is None:
        return None
    v = float(v) * scale
    return round(v, digits) if digits is not None else v


def to_run(a):
    return {
        "id": a.get("activityId"),
        "date": a.get("startTimeLocal"),
        "title": a.get("activityName") or "跑步",
        "dist": num(a.get("distance"), 1 / 1000, 3),
        "secs": num(a.get("movingDuration") or a.get("duration"), 1, 1),
        "avgHr": num(a.get("averageHR"), 1, 0),
        "maxHr": num(a.get("maxHR"), 1, 0),
        "cad": num(a.get("averageRunningCadenceInStepsPerMinute"), 1, 0),
        "stride": num(a.get("avgStrideLength"), 1 / 100, 3),
        "ascent": num(a.get("elevationGain"), 1, 0),
        "te": num(a.get("aerobicTrainingEffect"), 1, 1),
        "tss": num(a.get("trainingStressScore"), 1, 1),
    }


def login():
    from garminconnect import Garmin

    api = Garmin(os.environ["GARMIN_EMAIL"], os.environ["GARMIN_PASSWORD"])
    api.login()
    return api


def fetch_runs(api):
    runs, start = [], 0
    while start < MAX_ACTIVITIES:
        page = api.get_activities(start, PAGE)
        if not page:
            break
        runs += [to_run(a) for a in page if is_run(a)]
        start += PAGE
    return [r for r in runs if r["date"] and r["dist"] and r["secs"]]


def to_detail(raw):
    """把 Garmin 的逐點資料整理成逐公里分段和縮減過的曲線，刻意不保留經緯度。"""
    idx = {d["key"]: d["metricsIndex"] for d in raw.get("metricDescriptors") or [] if isinstance(d.get("metricsIndex"), int)}

    def col(sample, key):
        i = idx.get(key)
        m = sample.get("metrics") or []
        return m[i] if i is not None and i < len(m) else None

    rows = []
    for s in raw.get("activityDetailMetrics") or []:
        d, t = col(s, "sumDistance"), col(s, "sumMovingDuration") or col(s, "sumDuration")
        if d is None or t is None:
            continue
        cad = col(s, "directDoubleCadence") or col(s, "directRunCadence")
        if cad and cad < 120:  # 有些裝置只記單腳步頻
            cad *= 2
        rows.append({"d": d / 1000, "t": t, "hr": col(s, "directHeartRate"), "cad": cad, "el": col(s, "directElevation")})
    rows.sort(key=lambda r: r["t"])
    if len(rows) < 10 or rows[-1]["d"] < 0.5:
        return None

    def avg(rs, k):
        v = [r[k] for r in rs if r[k]]
        return round(sum(v) / len(v)) if v else None

    splits, start, km = [], 0, 1
    for i, r in enumerate(rows):
        last = i == len(rows) - 1
        if r["d"] >= km or (last and r["d"] - (km - 1) >= 0.1):
            seg = rows[start : i + 1]
            prev = rows[start - 1] if start else {"d": 0, "t": rows[0]["t"]}
            dist, secs = r["d"] - prev["d"], r["t"] - prev["t"]
            els = [x["el"] for x in seg if x["el"] is not None]
            gain = sum(max(0, b - a) for a, b in zip(els, els[1:])) if len(els) > 1 else None
            splits.append({"km": round(r["d"], 2), "dist": round(dist, 3), "secs": round(secs, 1), "hr": avg(seg, "hr"), "cad": avg(seg, "cad"), "gain": round(gain) if gain is not None else None})
            start, km = i + 1, km + 1

    step = max(1, len(rows) // DETAIL_POINTS)
    pts = []
    for i in range(0, len(rows), step):
        seg = rows[i : i + step]
        dd, dt = seg[-1]["d"] - (rows[i - 1]["d"] if i else 0), seg[-1]["t"] - (rows[i - 1]["t"] if i else rows[0]["t"])
        el = seg[-1]["el"]
        pts.append([round(seg[-1]["d"], 3), round(seg[-1]["t"]), round(dt / dd) if dd > 0.005 else None, avg(seg, "hr"), avg(seg, "cad"), round(el, 1) if el is not None else None])
    return {"splits": splits, "pts": pts}


def detail_name(activity_id, password):
    """檔名由密碼和活動編號雜湊而成，公開的 repo 看不出是哪一次活動；網頁用同樣方式算出檔名。"""
    return hashlib.sha256(f"{password}:{activity_id}".encode("utf-8")).hexdigest()[:20] + ".enc.json"


def fetch_details(api, runs, password):
    """只抓還沒有明細檔的跑步；抓不到曲線的也寫一個空檔，下次就不再重抓。"""
    n = 0
    for r in sorted(runs, key=lambda r: r["date"])[-DETAIL_RUNS:]:
        if not r.get("id"):
            continue
        path = os.path.join(DETAIL_DIR, detail_name(r["id"], password))
        if os.path.exists(path):
            continue
        try:
            d = to_detail(api.get_activity_details(r["id"], maxchart=4000, maxpoly=0))
        except Exception as e:
            print(f"抓不到 {r['date']} 的明細：{e}")
            continue
        write_blob(path, d, password)
        n += 1
        time.sleep(0.5)  # 避免短時間打太多次 Garmin
    return n


def write_blob(path, payload, password, **extra):
    blob = encrypt(payload, password)
    blob.update(extra)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(blob, f)


def encrypt(payload, password):
    salt, iv = os.urandom(16), os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, json.dumps(payload, ensure_ascii=False).encode("utf-8"), None)
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return {"v": 1, "kdf": "PBKDF2-SHA256", "iter": ITERATIONS, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}


def decrypt(blob, password):
    d = lambda k: base64.b64decode(blob[k])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=d("salt"), iterations=blob["iter"])
    key = kdf.derive(password.encode("utf-8"))
    return json.loads(AESGCM(key).decrypt(d("iv"), d("ct"), None))


def load_previous(password):
    try:
        with open(OUT, encoding="utf-8") as f:
            return decrypt(json.load(f), password)
    except Exception:
        return None


def main():
    for k in ("GARMIN_EMAIL", "GARMIN_PASSWORD", "DATA_PASSWORD"):
        if not os.environ.get(k):
            sys.exit(f"缺少 GitHub Secret：{k}")
    api = login()
    runs = fetch_runs(api)
    if not runs:
        sys.exit("沒有抓到任何跑步紀錄，保留舊的資料不覆蓋。")
    password = os.environ["DATA_PASSWORD"]
    n = fetch_details(api, runs, password)
    if n:
        print(f"新增 {n} 次跑步的明細")
    prev = load_previous(password) or {}
    want_ai = bool(os.environ.get("DEEPSEEK_API_KEY"))
    if prev.get("runs") == runs and (not want_ai or prev.get("analysis")):
        print("沒有新的跑步紀錄")
        return
    analysis = prev.get("analysis")
    if want_ai:
        try:
            from coach import analyze

            analysis = analyze(runs)
            print("已產生 AI 教練分析")
        except Exception as e:
            print(f"AI 分析失敗，沿用上一次的結果：{e}")
    updated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload = {"updated": updated, "runs": runs}
    if analysis:
        payload["analysis"] = analysis
    write_blob(OUT, payload, password, updated=updated, count=len(runs))
    print(f"已更新 {len(runs)} 筆跑步紀錄")


if __name__ == "__main__":
    main()

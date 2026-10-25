"""每天從 Garmin Connect 抓跑步紀錄，加密後寫入 data/runs.enc.json。

需要的環境變數（存在 GitHub Secrets）：
  GARMIN_EMAIL, GARMIN_PASSWORD  Garmin 帳號密碼
  DATA_PASSWORD                  儀表板解鎖用的密碼，用來加密資料
"""
import base64
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

OUT = os.path.join(os.path.dirname(__file__), "..", "data", "runs.enc.json")
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


def fetch_runs():
    from garminconnect import Garmin

    api = Garmin(os.environ["GARMIN_EMAIL"], os.environ["GARMIN_PASSWORD"])
    api.login()
    runs, start = [], 0
    while start < MAX_ACTIVITIES:
        page = api.get_activities(start, PAGE)
        if not page:
            break
        runs += [to_run(a) for a in page if is_run(a)]
        start += PAGE
    return [r for r in runs if r["date"] and r["dist"] and r["secs"]]


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


def unchanged(runs, password):
    try:
        with open(OUT, encoding="utf-8") as f:
            return decrypt(json.load(f), password)["runs"] == runs
    except Exception:
        return False


def main():
    for k in ("GARMIN_EMAIL", "GARMIN_PASSWORD", "DATA_PASSWORD"):
        if not os.environ.get(k):
            sys.exit(f"缺少 GitHub Secret：{k}")
    runs = fetch_runs()
    if not runs:
        sys.exit("沒有抓到任何跑步紀錄，保留舊的資料不覆蓋。")
    if unchanged(runs, os.environ["DATA_PASSWORD"]):
        print("沒有新的跑步紀錄")
        return
    updated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    blob = encrypt({"updated": updated, "runs": runs}, os.environ["DATA_PASSWORD"])
    blob["updated"] = updated
    blob["count"] = len(runs)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(blob, f)
    print(f"已更新 {len(runs)} 筆跑步紀錄")


if __name__ == "__main__":
    main()

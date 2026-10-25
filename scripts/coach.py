"""把跑步紀錄整理成摘要，請 DeepSeek 以跑步教練的角度給出分析與下週課表。"""
import json
import os
import urllib.request
from datetime import datetime, timedelta, timezone

SYSTEM = (
    "你是一位有國際認證的跑步教練，也具備運動科學背景。"
    "請根據使用者的 Garmin 跑步數據，用繁體中文（台灣用語）給出專業、具體、可執行的分析。"
    "每個判斷都要引用數據中的實際數字；資料不足就直說，不要臆測。"
    "不做醫療診斷，遇到受傷風險時建議減量或就醫。"
    "只輸出一個 JSON 物件，不要有其他文字。"
)

SCHEMA = """請輸出以下 JSON 結構：
{
  "headline": "一句話總結目前狀態，30 字以內",
  "status": "目前訓練狀態評估，2 到 4 句",
  "strengths": ["做得好的地方，每點一句，2 到 4 點"],
  "risks": ["需要注意的問題或風險，每點一句，1 到 4 點"],
  "plan": [{"day": "週一", "workout": "課表名稱與距離", "detail": "配速或心率目標、注意事項"}],
  "race_prediction": "依目前能力預估 5K、10K、半馬的完賽時間，並說明依據",
  "tips": ["跑姿、步頻、恢復或營養的具體建議，2 到 4 點"]
}
plan 必須剛好 7 天，從下週一排到週日，休息日也要列出。"""


def _date(r):
    return datetime.strptime(r["date"][:19], "%Y-%m-%d %H:%M:%S")


def _pace(secs, km):
    s = round(secs / km) if km else 0
    return f"{s // 60}:{s % 60:02d}"


def _hms(secs):
    s = round(secs)
    return f"{s // 3600}:{s % 3600 // 60:02d}:{s % 60:02d}" if s >= 3600 else f"{s // 60}:{s % 60:02d}"


def build_summary(runs, today=None):
    rs = sorted(runs, key=_date)
    today = today or datetime.now(timezone(timedelta(hours=8))).replace(tzinfo=None)
    monday = (today - timedelta(days=today.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)

    weeks = []
    for i in range(11, -1, -1):
        start = monday - timedelta(weeks=i)
        w = [r for r in rs if start <= _date(r) < start + timedelta(weeks=1)]
        weeks.append({"週一": start.strftime("%m/%d"), "km": round(sum(r["dist"] for r in w), 1), "次數": len(w)})

    def km_since(days):
        return sum(r["dist"] for r in rs if _date(r) >= today - timedelta(days=days))

    acute, chronic = km_since(7), km_since(28) / 4
    recent = [
        {
            "日期": _date(r).strftime("%Y-%m-%d"),
            "標題": r.get("title"),
            "km": round(r["dist"], 2),
            "配速": _pace(r["secs"], r["dist"]),
            "平均心率": r.get("avgHr"),
            "步頻": r.get("cad"),
            "步幅m": r.get("stride"),
            "爬升m": r.get("ascent"),
        }
        for r in rs[-20:]
    ]
    best = {}
    for name, km in (("3K", 3), ("5K", 5), ("10K", 10), ("半馬", 21.0975)):
        c = [r for r in rs if r["dist"] >= km * 0.98]
        if c:
            b = min(c, key=lambda r: r["secs"] / r["dist"])
            best[name] = {"推估時間": _hms(b["secs"] / b["dist"] * km), "日期": _date(b).strftime("%Y-%m-%d")}
    max_hrs = sorted((r["maxHr"] for r in rs if r.get("maxHr")), reverse=True)
    return {
        "今天": today.strftime("%Y-%m-%d") + "（週" + "一二三四五六日"[today.weekday()] + "）",
        "總跑步次數": len(rs),
        "近12週每週跑量": weeks,
        "近7天km": round(acute, 1),
        "近28天週平均km": round(chronic, 1),
        "急慢性負荷比_以距離計": round(acute / chronic, 2) if chronic else None,
        "資料中最高心率": max_hrs[1] if len(max_hrs) > 1 else (max_hrs[0] if max_hrs else None),
        "各距離最快平均配速推估": best,
        "最近20次跑步": recent,
    }


def analyze(runs):
    key = os.environ["DEEPSEEK_API_KEY"]
    model = os.environ.get("DEEPSEEK_MODEL") or "deepseek-chat"
    base = (os.environ.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com").rstrip("/")
    summary = build_summary(runs)
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": SCHEMA + "\n\n以下是數據：\n" + json.dumps(summary, ensure_ascii=False)},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.6,
        "max_tokens": 2000,
    }
    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        content = json.loads(resp.read())["choices"][0]["message"]["content"]
    data = json.loads(content)
    for k in ("headline", "status", "plan"):
        if not data.get(k):
            raise ValueError(f"回傳缺少 {k}")
    data["generated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    data["model"] = model
    return data

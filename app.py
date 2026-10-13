# -*- coding: utf-8 -*-
"""
SEU 素质讲座抢座助手 - 本地服务
流程: 浏览器登录(SSO) -> 提取Cookie -> 查询讲座列表 -> 定时调用 yySave.do 抢座
"""
import base64
import hashlib
import json
import re
import threading
import time
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

import requests
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

ROOT = Path(__file__).parent
COOKIE_FILE = ROOT / "session_cookies.json"
BASE = "https://ehall.seu.edu.cn/gsapp/sys/jzxxtjapp"
APP_PAGE = BASE + "/*default/index.do"
AUTH = "https://auth.seu.edu.cn/auth/casback"
SERVICE = "http://ehall.seu.edu.cn/login?service=https://ehall.seu.edu.cn/new/index.html"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")

# 全局会话(Cookie 鉴权, _WEU 自动滚动更新)
# 注意:会话默认头必须保持最小!requests 会把会话头合并进每个请求,
# 若默认带 X-Requested-With 等头,导航类 GET 也会被后端当成 AJAX 直接 401
session = requests.Session()
session.trust_env = False  # 绕过系统代理(Reqable 等抓包代理的 MITM 证书会导致 SSL 校验失败)
session.headers.update({"User-Agent": UA})
http_lock = threading.RLock()

# 讲座应用 API 请求头(在 api_post 里按次传入,不进会话默认头)
API_HEADERS = {
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Origin": "https://ehall.seu.edu.cn",
    "Referer": APP_PAGE,
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
}

state = {
    "login": "none",        # none | processing | logged_in | failed
    "login_msg": "",
    "server_offset": 0.0,  # 服务器时间 - 本地时间(秒)
    "login_trace": [],     # 登录/会话链路每一步的详细追踪
}


def _trace(msg):
    state["login_trace"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    del state["login_trace"][:-80]


def save_cookies():
    try:
        data = [{"name": c.name, "value": c.value, "domain": c.domain,
                 "path": c.path} for c in session.cookies]
        COOKIE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=1),
                               encoding="utf-8")
    except Exception:
        pass


def load_cookies():
    try:
        if COOKIE_FILE.exists():
            for c in json.loads(COOKIE_FILE.read_text(encoding="utf-8")):
                ck = requests.cookies.create_cookie(
                    name=c["name"], value=c["value"],
                    domain=c.get("domain") or "ehall.seu.edu.cn",
                    path=c.get("path") or "/")
                session.cookies.set_cookie(ck)
            return True
    except Exception:
        pass
    return False

_ocr_state = {"ocr": None, "tried": False}


def get_ocr():
    """可选的 ddddocr 验证码识别(未安装则返回 None,使用手动模式)"""
    if not _ocr_state["tried"]:
        _ocr_state["tried"] = True
        try:
            import ddddocr
            # 不同版本类名大小写不同: DdddOcr / Ddddocr
            cls = getattr(ddddocr, "DdddOcr", None) or getattr(ddddocr, "Ddddocr")
            try:
                # 验证码为纯4位数字,优先限定数字字符集提高准确率
                _ocr_state["ocr"] = cls(show_ad=False, charset_range="0123456789")
            except TypeError:
                _ocr_state["ocr"] = cls(show_ad=False)
        except Exception:
            _ocr_state["ocr"] = None
    return _ocr_state["ocr"]


# ---------------- HTTP 接口封装 ----------------

def api_post(path, data=None, timeout=10):
    url = f"{BASE}/{path}"
    with http_lock:
        r = session.post(url, data=data if data is not None else {},
                         headers=dict(API_HEADERS), timeout=timeout)
    # _WEU 等会随每个响应滚动,每次调用后都持久化,防止重启后用到过期 Cookie
    save_cookies()
    r.raise_for_status()
    return r


def fetch_lectures():
    r = api_post("hdyy/queryActivityList.do?_=%d" % int(time.time() * 1000),
                 {"pageIndex": 1, "pageSize": 50, "sortField": "", "sortOrder": ""})
    data = r.json()
    items = []
    for it in (data.get("datas") or []):
        def _int(v):
            try:
                return int(v or 0)
            except (TypeError, ValueError):
                return 0
        items.append({
            "wid": it.get("WID"),
            "title": it.get("JZMC"),
            "category": it.get("JZXL_DISPLAY"),
            "speaker": it.get("ZJR"),
            "start_time": it.get("JZSJ"),
            "end_time": it.get("HDJSSJ"),
            "place": it.get("JZDD"),
            "total": _int(it.get("HDZRS")),
            "booked": _int(it.get("YYRS")),
            "book_open": it.get("YYKSSJ"),
            "book_end": it.get("YYJSSJ"),
            "fbzt": it.get("FBZT"),
        })
    save_cookies()  # _WEU 等会随响应滚动,及时持久化
    return items


# ---------------- 账号密码直接登录(逆向 auth.seu.edu.cn 协议) ----------------

def do_login_direct(username: str, password: str):
    """
    1. getChiperKey 拿 RSA 公钥(-/+ 与 _// 等价替换的 base64)
    2. RSA PKCS#1 v1.5 加密密码(与前端 JSEncrypt 行为一致)
    3. casLogin 提交 JSON,拿 redirectUrl(内含 ST ticket),TGT cookie 自动入会话
    4. loginRedirect 跟随 302 链,ehall 会话 Cookie(GS_SESSIONID 等)自动入会话
    密码仅在内存中短暂存在,不落盘。
    """
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA

    with http_lock:
        session.cookies.clear()
        # 独立认证会话:完整保留 CHIPER_UID / TGT 等认证 Cookie
        temp = requests.Session()
        temp.trust_env = False  # 直连,绕过系统代理
        temp.headers.update({
            "Origin": "https://auth.seu.edu.cn",
            "Referer": "https://auth.seu.edu.cn/dist/",
            "User-Agent": UA,
        })

        # 1. 获取公钥(响应 Set-Cookie: CHIPER_UID)
        r = temp.post(f"{AUTH}/getChiperKey", json={}, timeout=15)
        r.raise_for_status()
        key_data = r.json()
        if not key_data.get("success"):
            raise RuntimeError("获取公钥失败: " + str(key_data.get("info")))
        # 服务端把标准 base64 的 + 替换成 -、/ 替换成 _(前端定制解码器 ma["-"]=62, ma["_"]=63)
        pk_b64 = key_data["publicKey"].replace("-", "+").replace("_", "/")
        key = RSA.import_key(base64.b64decode(pk_b64))

        # 2. RSA 加密密码(与前端 JSEncrypt pkcs1pad2 一致)
        cipher = PKCS1_v1_5.new(key)
        encrypted = base64.b64encode(cipher.encrypt(password.encode("utf-8"))).decode("ascii")
        del password  # 立即丢弃明文引用

        # 3. 提交登录(响应 Set-Cookie: TGT)
        finger_print = "stable_" + hashlib.md5(
            (username + UA).encode("utf-8")).hexdigest()
        payload = {
            "service": SERVICE,
            "username": username,
            "password": encrypted,
            "captcha": "",
            "rememberMe": False,
            "loginType": "account",
            "wxBinded": False,
            "mobilePhoneNum": "",
            "fingerPrint": finger_print,
        }
        r = temp.post(f"{AUTH}/casLogin", json=payload, timeout=15)
        r.raise_for_status()
        data = r.json()
        if not data.get("success"):
            raise RuntimeError(data.get("info") or json.dumps(data, ensure_ascii=False)[:120])
        redirect_url = data.get("redirectUrl")
        if not redirect_url:
            raise RuntimeError("登录成功但未返回 redirectUrl")

        # 4. loginRedirect -> 302 链 -> ehall 会话(redirectUrl 已是编码形式,原样拼接)
        r = temp.get(f"{AUTH}/loginRedirect?redirectUrl={redirect_url}",
                     allow_redirects=True, timeout=20)
        r.raise_for_status()

        # 5. 转移全部 Cookie 到全局会话
        for c in temp.cookies:
            session.cookies.set_cookie(c)

        # 6. 建立应用级会话:appShow 拿带 gid_ 的入口 → verifyTgt 换 ticket → 进应用
        _establish_app_session()
        save_cookies()  # 即使后面验证失败,也保留半成品会话便于诊断重试

        # 7. 验证会话
        try:
            fetch_lectures()
        except Exception as e:
            raise RuntimeError(f"登录流程完成但会话验证失败: {e}")

        state["login"] = "logged_in"
        state["login_msg"] = f"账号密码登录成功(用户 {username[:3]}***)"
        save_cookies()


# 浏览器导航请求头(已实测:带这些头逐跳访问应用入口,GS_SESSIONID/_WEU 正常签发)
DOC_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Language": "zh-CN,zh;q=0.9",
}


def _follow_hops(url, max_hops=10):
    """手动逐跳跟随 302(比 requests 自动跟随更可控,Set-Cookie 逐跳保存)"""
    for _ in range(max_hops):
        r = session.get(url, headers=dict(DOC_HEADERS, Referer="https://ehall.seu.edu.cn/new/index.html",
                                          **{"Sec-Fetch-Site": "none"}), allow_redirects=False, timeout=25)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if not loc:
                return r
            if loc.startswith("/"):
                from urllib.parse import urlparse
                u = urlparse(url)
                loc = f"{u.scheme}://{u.netloc}{loc}"
            url = loc
            continue
        return r
    return r


def _establish_app_session():
    """完成 门户→应用 的会话转换(逆向浏览器跳转链):
    1. 以页面请求方式访问应用入口(不带 XHR 头,否则后端直接 401)
       → 302 到认证登录页,从 Location 解析 service(应用入口 URL)
    2. verifyTgt:用 TGT 换取绑定应用 service 的 ST ticket
    3. GET 带 ticket 的 redirectUrl → 签发 GS_SESSIONID / _WEU
    每一步记录到 state["login_trace"]
    """
    from urllib.parse import unquote

    def has_app_session():
        return any(c.name == "GS_SESSIONID" and c.value for c in session.cookies)

    if has_app_session():
        _trace("应用会话已存在(GS_SESSIONID)")
        return True

    # 页面式请求头:与实测成功的浏览器头完全一致
    sh = {
        "User-Agent": UA,
        "Referer": "https://ehall.seu.edu.cn/new/index.html",
        "Accept": DOC_HEADERS["Accept"],
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Language": "zh-CN,zh;q=0.9",
    }

    # ⓪ appShow:门户的应用入口网关,签发带 t_s / gid_ 授权参数的应用 URL
    #    (gid_ 是应用授权令牌,缺它则应用入口 401)
    service = None
    try:
        r = session.get("https://ehall.seu.edu.cn/appShow?appId=5736122417335219",
                        headers=sh, allow_redirects=False, timeout=25)
        loc = r.headers.get("Location", "")
        _trace(f"⓪ appShow → {r.status_code}"
               + (f" Location: {loc[:180]}" if loc else ""))
        if loc:
            service = loc
    except Exception as e:
        _trace(f"⓪ appShow 异常: {e}")

    if not service:
        # 兜底:直接访问应用入口,期望 302 到登录页并解析 service
        service = "http://ehall.seu.edu.cn/gsapp/sys/jzxxtjapp/*default/index.do"
        try:
            r = session.get(APP_PAGE, headers=sh, allow_redirects=False, timeout=25)
            loc = r.headers.get("Location", "")
            _trace(f"① GET 应用入口 → {r.status_code}"
                   + (f" Location: {loc[:180]}" if loc else ""))
            if "service=" in loc:
                service = unquote(loc.split("service=", 1)[1])
                _trace(f"① 解析 service: {service[:180]}")
        except Exception as e:
            _trace(f"① GET 应用入口异常: {e}")

    # verifyTgt:TGT 换应用专属 ST ticket
    try:
        r = session.post(
            f"{AUTH}/verifyTgt",
            json={"service": service},
            headers={
                "Origin": "https://auth.seu.edu.cn",
                "Referer": "https://auth.seu.edu.cn/dist/",
                "User-Agent": UA,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=20)
        _trace(f"② verifyTgt → {r.status_code}: {r.text[:180]}")
        data = r.json()
        if data.get("success") and data.get("redirectUrl"):
            ru = data["redirectUrl"]
            if not ru.startswith("http"):
                ru = unquote(ru)
            # 带 ticket 访问应用入口,逐跳跟随 302,签发 GS_SESSIONID / _WEU
            r = _follow_hops(ru)
            _trace(f"③ GET 带 ticket 入口(逐跳) → {r.status_code} 最终: {r.url[:160]}")
    except Exception as e:
        _trace(f"②③ verifyTgt/带ticket访问异常: {e}")

    if not has_app_session():
        # 最后兜底:直接走应用入口完整跳转链
        try:
            r = _follow_hops(APP_PAGE)
            _trace(f"④ 兜底 GET 应用入口(逐跳) → {r.status_code} 最终: {r.url[:160]}")
        except Exception as e:
            _trace(f"④ 兜底异常: {e}")
    _trace(f"⑤ 应用会话结果: {'成功' if has_app_session() else '失败'} | "
           f"当前Cookie: {', '.join(sorted({c.name for c in session.cookies}))}")
    return has_app_session()


# ---------------- 登录(Playwright 打开浏览器,用户手动完成 SSO) ----------------

def do_login():
    try:
        state["login"] = "processing"
        state["login_msg"] = "正在打开浏览器…"
        from playwright.sync_api import sync_playwright
        with http_lock:
            session.cookies.clear()
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(channel="chrome", headless=False)
            except Exception:
                browser = p.chromium.launch(channel="msedge", headless=False)
            context = browser.new_context(user_agent=UA)
            page = context.new_page()
            try:
                page.goto(APP_PAGE, wait_until="domcontentloaded", timeout=60000)
            except Exception:
                pass  # SSO 跳转中途 domcontentloaded 超时不算失败
            state["login_msg"] = "请在弹出的浏览器窗口中完成统一认证登录(最长等待10分钟)"

            deadline = time.time() + 600
            ok = False
            while time.time() < deadline:
                try:
                    cookies = context.cookies()
                except Exception:
                    cookies = []
                names = {c["name"] for c in cookies}
                if "GS_SESSIONID" in names or "_WEU" in names:
                    ok = True
                    break
                time.sleep(1.0)

            if not ok:
                state["login"] = "failed"
                state["login_msg"] = "登录超时(10分钟),请重新发起登录"
                try:
                    browser.close()
                except Exception:
                    pass
                return

            # 提取 Cookie 到全局会话
            with http_lock:
                session.cookies.clear()
                for c in cookies:
                    dom = c.get("domain") or ""
                    if "seu.edu.cn" not in dom:
                        continue
                    ck = requests.cookies.create_cookie(
                        name=c["name"], value=c["value"],
                        domain=dom.lstrip("."),
                        path=c.get("path") or "/",
                    )
                    session.cookies.set_cookie(ck)

            # 验证 Cookie 是否真的可用
            try:
                fetch_lectures()
            except Exception as e:
                state["login"] = "failed"
                state["login_msg"] = f"Cookie 验证失败: {e}"
                try:
                    browser.close()
                except Exception:
                    pass
                return

            state["login"] = "logged_in"
            state["login_msg"] = "登录成功,Cookie 已提取并验证通过"
            save_cookies()
            try:
                browser.close()
            except Exception:
                pass
    except Exception as e:
        state["login"] = "failed"
        state["login_msg"] = f"登录异常: {e}"


# ---------------- 抢座任务 ----------------

class Task:
    def __init__(self, wid, title, mode, start_ts, lead, max_attempts, full_retry):
        self.wid = wid
        self.title = title
        self.mode = mode  # auto | manual
        self.start_ts = start_ts          # 本地时钟的开抢时刻(epoch 秒)
        self.lead = lead                  # 提前量(秒)
        self.max_attempts = max_attempts
        self.full_retry = full_retry      # 人数已满时是否继续重试
        # 开始时间即本机时钟时刻(前端自动把服务器开放时刻换算成本机时间填入)
        self.target_ts = start_ts - lead
        self.state = "waiting"            # waiting | running | done | failed
        self.log = []
        self.captcha = None                # 最近一次验证码图(data URI)
        self.awaiting_input = False
        self.input_event = threading.Event()
        self.input_value = None
        self.result = None
        self.stop_flag = False
        self.attempts = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def add_log(self, msg):
        self.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        del self.log[:-200]

    def fail(self, msg):
        self.state = "failed"
        self.result = {"success": False, "msg": msg}
        self.add_log(f"❌ 任务结束: {msg}")

    def submit_captcha(self, code):
        self.input_value = code
        self.awaiting_input = False
        self.input_event.set()

    # ---- 主循环 ----
    def run(self):
        self.add_log(f"任务创建: {self.title[:40]}")
        self.add_log(f"模式: {'自动OCR' if self.mode == 'auto' else '手动输入验证码'} | "
                     f"计划开始: {datetime.fromtimestamp(self.start_ts)} | 提前 {self.lead}s")
        while time.time() < self.target_ts:
            if self.stop_flag:
                return self.fail("已手动停止")
            self.state = "waiting"
            time.sleep(min(0.5, max(0.02, self.target_ts - time.time())))

        self.state = "running"
        self.add_log("⏰ 到点,开始抢座!")

        ocr = get_ocr()
        if self.mode == "auto" and ocr is None:
            self.add_log("⚠ 未安装 ddddocr,自动模式退化为手动输入")
            self.mode = "manual"

        vcode_fails = 0  # 连续验证码错误计数(用于自动降级)
        for i in range(self.max_attempts):
            if self.stop_flag:
                return self.fail("已手动停止")
            self.attempts = i + 1
            try:
                code = self.get_code(ocr)
                if not code:
                    continue
                resp = api_post("hdyy/yySave.do?_=%d" % int(time.time() * 1000),
                                {"paramJson": json.dumps(
                                    {"HD_WID": self.wid, "vcode": code},
                                    ensure_ascii=False)})
                try:
                    data = resp.json()
                except Exception:
                    self.add_log(f"响应非JSON: {resp.text[:80]}")
                    time.sleep(0.3)
                    continue

                if data.get("success"):
                    self.result = {"success": True, "msg": "预约成功!"}
                    self.state = "done"
                    self.add_log("🎉 预约成功!!")
                    return

                msg = data.get("msg") or json.dumps(data, ensure_ascii=False)[:100]
                self.add_log(f"第{i + 1}次尝试失败: {msg}")

                if "验证码" in msg:
                    vcode_fails += 1
                    if self.mode == "auto" and vcode_fails >= 6:
                        self.mode = "manual"
                        self.add_log("⚠ 自动OCR连续6次验证码错误,已自动切换为手动输入模式")
                    continue  # 验证码错误,立即刷新重试
                if "已预约" in msg or "重复" in msg:
                    self.result = {"success": True, "msg": "已有预约: " + msg}
                    self.state = "done"
                    return
                if "满" in msg:
                    if not self.full_retry:
                        return self.fail(msg)
                    time.sleep(0.5)
                    continue
                if any(k in msg for k in ("未开放", "未开始", "不在", "时间", "开始")):
                    vcode_fails = 0  # 等开放不算验证码失误
                    time.sleep(0.3)
                    continue
                time.sleep(0.4)
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == 401:
                    return self.fail("登录会话已失效(401):可能账号在其他设备/浏览器重新登录过。"
                                     "请在页面重新登录后再启动任务")
                self.add_log(f"网络错误: {e}")
                time.sleep(0.5)
            except requests.RequestException as e:
                self.add_log(f"网络错误: {e}")
                time.sleep(0.5)
            except Exception as e:
                self.add_log(f"异常: {e}")
                time.sleep(0.5)
        self.fail("达到最大尝试次数,仍未成功")

    # ---- 取一张验证码(返回 b64;同时更新 self.captcha 供页面显示) ----
    def _fetch_vcode_b64(self):
        try:
            resp = api_post("hdyy/vcode.do?_=%d" % int(time.time() * 1000))
            data = resp.json()
        except requests.HTTPError:
            raise  # 401(会话失效)等由外层统一快速失败,不在此空转
        except Exception as e:
            self.add_log(f"获取验证码失败: {e}")
            time.sleep(0.3)
            return None
        if not data.get("success"):
            self.add_log("获取验证码失败(接口返回 success=false)")
            time.sleep(0.3)
            return None
        img = data.get("result") or ""
        if img.startswith("data:"):
            b64 = img.split(",", 1)[1]
            self.captcha = img
        else:
            b64 = img
            self.captcha = "data:image/png;base64," + img
        return b64

    # ---- 获取验证码(auto: OCR + 4位数字校验 / manual: 等待网页输入) ----
    def get_code(self, ocr):
        b64 = self._fetch_vcode_b64()
        if not b64:
            return None

        if self.mode == "auto" and ocr is not None:
            code = None
            for round_i in range(3):
                try:
                    code = ocr.classification(base64.b64decode(b64))
                    code = (code or "").strip().replace(" ", "")
                except Exception as e:
                    self.add_log(f"OCR 失败: {e}")
                    code = None
                # 规则校验:必须4位纯数字(实测该验证码为4位数字)
                if code and re.fullmatch(r"\d{4}", code):
                    self.add_log(f"OCR 识别: {code}")
                    return code
                self.add_log(f"OCR 结果 {code!r} 不是4位数字,刷新验证码重试({round_i + 1}/3)")
                b64 = self._fetch_vcode_b64()
                if not b64:
                    return None
            self.add_log("连续3轮不合规,放弃本轮(外层自动重试)")
            return None

        # 手动输入
        self.awaiting_input = True
        self.input_event.clear()
        self.add_log("⌨ 等待在网页中输入验证码(4位数字)…")
        if self.input_event.wait(180):
            v = (self.input_value or "").strip()
            self.input_value = None
            return v or None
        self.awaiting_input = False
        self.add_log("输入超时(180s),跳过本轮")
        return None


current_task: Task | None = None
task_lock = threading.Lock()


# ---------------- FastAPI 路由 ----------------

app = FastAPI(title="SEU 素质讲座抢座助手")


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


class DirectLogin(BaseModel):
    username: str
    password: str


@app.post("/api/login/direct")
def login_direct(d: DirectLogin):
    """账号密码直接登录(无需打开浏览器)"""
    if state["login"] == "processing":
        return JSONResponse({"ok": False, "msg": "登录进行中,请稍候"}, status_code=400)
    if not d.username.strip() or not d.password:
        return JSONResponse({"ok": False, "msg": "请输入账号和密码"}, status_code=400)
    state["login"] = "processing"
    state["login_msg"] = "正在提交登录…"
    try:
        do_login_direct(d.username.strip(), d.password)
        return {"ok": True, "msg": state["login_msg"]}
    except Exception as e:
        state["login"] = "failed"
        state["login_msg"] = f"登录失败: {e}"
        return JSONResponse({"ok": False, "msg": state["login_msg"]}, status_code=400)


@app.post("/api/login/start")
def login_start():
    if state["login"] == "processing":
        return {"ok": False, "msg": "登录进行中,请稍候"}
    threading.Thread(target=do_login, daemon=True).start()
    return {"ok": True}


@app.get("/api/login/status")
def login_status():
    return {
        "login": state["login"],
        "msg": state["login_msg"],
        "cookie_count": len(session.cookies) if state["login"] == "logged_in" else 0,
    }


@app.get("/api/debug/state")
def debug_state():
    """诊断:当前 Cookie 概况 + 应用会话/讲座接口可用性(不泄露 Cookie 值)"""
    names = sorted({f"{c.name}@{c.domain}{c.path}" for c in session.cookies})
    result = {"cookies": names, "app_page": None, "lectures": None}
    try:
        r = session.get(APP_PAGE, allow_redirects=True, timeout=20)
        result["app_page"] = {"status": r.status_code, "url": r.url[:120]}
    except Exception as e:
        result["app_page"] = {"error": str(e)[:200]}
    try:
        items = fetch_lectures()
        result["lectures"] = {"ok": True, "count": len(items)}
    except Exception as e:
        result["lectures"] = {"error": str(e)[:200]}
    return result


@app.get("/api/lectures")
def lectures():
    if state["login"] != "logged_in":
        return JSONResponse({"ok": False, "msg": "尚未登录"}, status_code=400)
    try:
        return {"ok": True, "items": fetch_lectures()}
    except Exception as e:
        return JSONResponse({"ok": False, "msg": f"查询失败: {e}"}, status_code=500)


@app.get("/api/time")
def time_sync():
    """用响应 Date 头同步服务器时间,得到 本地->服务器 的偏移"""
    if state["login"] != "logged_in":
        return JSONResponse({"ok": False, "msg": "尚未登录"}, status_code=400)
    try:
        r = api_post("hdyy/getSetting.do")
        d = r.headers.get("Date")
        if d:
            server_ts = parsedate_to_datetime(d).timestamp()
            state["server_offset"] = server_ts - time.time()
        return {
            "ok": True,
            "offset": round(state["server_offset"], 3),
            "server_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception as e:
        return JSONResponse({"ok": False, "msg": str(e)}, status_code=500)


class TaskStart(BaseModel):
    wid: str
    title: str = ""
    mode: str = "manual"          # manual | auto
    start_at: str = ""            # "YYYY-MM-DD HH:mm:ss" 本地时间,空=立即
    lead_seconds: float = 0.5
    max_attempts: int = 100
    full_retry: bool = False


@app.post("/api/task/start")
def task_start(t: TaskStart):
    global current_task
    with task_lock:
        if current_task and current_task.state in ("waiting", "running"):
            return JSONResponse({"ok": False, "msg": "已有任务进行中,请先停止"}, status_code=400)
        if state["login"] != "logged_in":
            return JSONResponse({"ok": False, "msg": "尚未登录"}, status_code=400)
        if t.mode not in ("manual", "auto"):
            return JSONResponse({"ok": False, "msg": "mode 必须是 manual 或 auto"}, status_code=400)
        ts = time.time()
        if t.start_at:
            try:
                ts = datetime.strptime(t.start_at, "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                return JSONResponse({"ok": False, "msg": "时间格式应为 YYYY-MM-DD HH:mm:ss"}, status_code=400)
        current_task = Task(t.wid, t.title or t.wid, t.mode, ts,
                            t.lead_seconds, t.max_attempts, t.full_retry)
    return {"ok": True}


@app.post("/api/task/stop")
def task_stop():
    if current_task:
        current_task.stop_flag = True
    return {"ok": True}


@app.get("/api/task/status")
def task_status():
    if not current_task:
        return {"state": "none"}
    t = current_task
    return {
        "state": t.state,
        "title": t.title,
        "mode": t.mode,
        "attempts": t.attempts,
        "log": t.log[-40:],
        "captcha": t.captcha if (t.awaiting_input or t.state == "running") else None,
        "awaiting_input": t.awaiting_input,
        "result": t.result,
        "remaining": round(max(0.0, t.target_ts - time.time()), 1) if t.state == "waiting" else 0,
    }


class CaptchaIn(BaseModel):
    code: str


@app.post("/api/task/captcha")
def task_captcha(c: CaptchaIn):
    if current_task:
        current_task.submit_captcha(c.code)
        return {"ok": True}
    return JSONResponse({"ok": False, "msg": "无任务"}, status_code=400)


class TestIn(BaseModel):
    wid: str


@app.post("/api/test")
def test_flow(x: TestIn):
    """只测试 appiontCheck + vcode 两个接口,不提交预约"""
    try:
        check = api_post("hdyy/appiontCheck.do", {"wid": x.wid}).json()
    except Exception as e:
        return JSONResponse({"ok": False, "msg": f"appiontCheck 失败: {e}"}, status_code=500)
    try:
        v = api_post("hdyy/vcode.do?_=%d" % int(time.time() * 1000)).json()
    except Exception as e:
        return JSONResponse({"ok": False, "msg": f"vcode 失败: {e}"}, status_code=500)
    cap = v.get("result") or ""
    if cap and not cap.startswith("data:"):
        cap = "data:image/png;base64," + cap
    return {"ok": True, "check": check, "captcha": cap}


@app.get("/api/debug/chain")
def debug_chain():
    """用当前会话重跑一遍 门户→应用 会话建立链,返回逐步追踪"""
    if not any(c.name == "TGT" for c in session.cookies):
        return JSONResponse({"ok": False, "msg": "当前无 TGT(未登录或已重启丢失)"}, status_code=400)
    ok = _establish_app_session()
    try:
        lec = fetch_lectures()
        lec_res = {"ok": True, "count": len(lec)}
    except Exception as e:
        lec_res = {"ok": False, "error": str(e)[:200]}
    return {"ok": ok, "trace": state["login_trace"], "lectures": lec_res}


# 启动时恢复上次会话
if load_cookies():
    try:
        fetch_lectures()
        state["login"] = "logged_in"
        state["login_msg"] = "已从本地保存的会话恢复(无需重新登录)"
    except Exception:
        session.cookies.clear()
        try:
            COOKIE_FILE.unlink()
        except Exception:
            pass
        state["login"] = "none"

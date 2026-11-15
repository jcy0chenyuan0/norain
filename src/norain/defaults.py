"""安装时写进 cfg.toml 的默认三类名单。

来源是本机 2026-11-15 正在运行的那套代理 C:\\Users\\j\\proxy-suite：
  * 白名单 PROXY_DOMAINS      sing-box.json 里 route.rules「domain_suffix → proxy」的那一组，
                              即原先强制走代理的站点（OpenAI / Claude / Google / GitHub / 维基 等）。
  * 黑名单 DIRECT_DOMAINS     空列表。原配置没有显式直连域名，国内直连由 geosite-cn + geoip-cn
                              规则集（routing.rule_set）承担；这里只在需要时补单条。
  * 蓝名单 ISOLATION_ALLOWLIST network-guard.ps1 的 $allowSites：杀开关（阻断）期间仍允许访问的站点。

改默认值只改这个文件；examples/cfg.toml 是给人看的完整示例，两处要一致。
"""

from __future__ import annotations

PROXY_DOMAINS = [
    'openai.com', 'chatgpt.com', 'chatgpt.livekit.cloud', 'oaistatic.com', 'oaiusercontent.com',
    'openai.org', 'sora.com', 'openaiapi-site.azureedge.net', 'identrust.com', 'statsig.com',
    'featuregates.org', 'intercom.io', 'browser-intake-datadoghq.com', 'claude.com',
    'claude.ai', 'anthropic.com', 'anthropic.ai', 'claudeusercontent.com', 'cla.st',
    'usefathom.com', 'x.com', 'twitter.com', 'twimg.com', 't.co', 'ads-twitter.com',
    'twitterinc.com', 'gemini.google.com', 'google.com', 'googleapis.com', 'gstatic.com',
    'googleusercontent.com', 'googlevideo.com', 'gvt1.com', 'gvt2.com', 'withgoogle.com',
    'google-analytics.com', 'googletagmanager.com', 'youtube.com', 'youtu.be', 'ytimg.com',
    'youtube-nocookie.com', 'ggpht.com', 'wikipedia.org', 'wikimedia.org', 'wikidata.org',
    'mediawiki.org', 'wikimediafoundation.org', 'wiktionary.org', 'wikisource.org',
    'wikibooks.org', 'wikiquote.org', 'wikinews.org', 'wikivoyage.org', 'wikiversity.org',
    'github.com', 'githubusercontent.com', 'githubassets.com', 'github.io', 'ghcr.io',
    'github-cloud.s3.amazonaws.com', 'npmjs.org', 'npmjs.com', 'pypi.org', 'pythonhosted.org',
    'docker.com', 'docker.io', 'dockerhub.com', 'huggingface.co', 'huggingface.com', 'hf.co',
    'hf.space', 'anthropic.org', 'claude.dev', 'sentry.io', 'statsigcdn.com', 'segment.io',
    'intercomcdn.com', 'challenges.cloudflare.com', 'ippure.com', 'ipinfo.io', 'cf.999831.xyz',
    'myip.ipip.net', 'ipify.org', 'ipwho.is', 'ipapi.co', 'freeipapi.com', 'hiofd.com',
]

# 与当前 sing-box.json 一致：没有显式直连域名，国内流量靠规则集。
DIRECT_DOMAINS: list[str] = []

ISOLATION_ALLOWLIST = [
    'deepseek.com', 'api.deepseek.com', 'chat.deepseek.com', 'www.bilibili.com', 'bilibili.com',
    'api.bilibili.com', 'www.zhihu.com', 'zhihu.com', 'api.zhihu.com', 'hdslb.com', 'zhimg.com',
    'bilivideo.com',
]

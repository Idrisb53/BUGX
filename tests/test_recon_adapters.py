"""Command construction and output parsing for the 10 recon adapters."""

import json

import pytest

from bugx.modules.recon.registry import RECON_ADAPTERS

A = {a.key: a for a in RECON_ADAPTERS}
H1 = {"required_headers": {"X-HackerOne-Research": "idris4hack"}, "rate_limit": 2, "concurrency": 2}


def test_registry_has_ten_unique_tools():
    assert [a.key for a in RECON_ADAPTERS] == [
        "subfinder", "amass", "dnsx", "httpx", "nmap", "naabu", "katana", "whatweb", "tlsx", "cloudlist"]
    for adapter in RECON_ADAPTERS:
        assert adapter.module == "recon" and adapter.binaries and adapter.install_hint()


def test_subfinder(ctx):
    c = ctx(policy=H1)
    assert A["subfinder"].build_args(c, "example.com") == ["-d", "example.com", "-silent", "-oJ", "-rl", "2"]
    out = '{"host":"api.example.com","source":"crtsh"}\n{"host":"API.example.com","source":"x"}\n'
    items = A["subfinder"].parse(c, out, "", "example.com")
    assert items[0] == {"type": "host", "asset": "api.example.com", "source": "crtsh"}
    assert A["subfinder"].parse(c, "a.example.com\nb.example.com\n", "", "example.com")[1]["asset"] == "b.example.com"


def test_amass_passive_and_filtered(ctx):
    c = ctx()
    args = A["amass"].build_args(c, "example.com")
    assert args[:4] == ["enum", "-passive", "-d", "example.com"]
    out = "www.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)\nevil.com\nexample.com.evil.net\n"
    assert [i["asset"] for i in A["amass"].parse(c, out, "", "example.com")] == ["www.example.com"]


def test_dnsx_batch_stdin(ctx):
    c = ctx(targets=["a.example.com", "https://b.example.com/x"], policy=H1)
    assert A["dnsx"].stdin(c, None) == "a.example.com\nb.example.com\n"
    assert "-json" in A["dnsx"].build_args(c, None)
    row = {"host": "a.example.com", "a": ["1.1.1.1"], "cname": ["cdn.vendor.net."]}
    items = A["dnsx"].parse(c, json.dumps(row), "", None)
    assert items[0]["type"] == "dns" and items[1] == {"type": "host", "asset": "cdn.vendor.net", "source": "cname of a.example.com"}


def test_httpx_rejects_python_client_and_sends_headers(ctx):
    assert A["httpx"].binaries[0] == "httpx-toolkit"
    assert A["httpx"].verify_binary("/usr/bin/httpx", "HTTPX A next generation HTTP client") is not None
    assert A["httpx"].verify_binary("/usr/bin/httpx-toolkit", "projectdiscovery.io v1.9.0") is None
    c = ctx(targets=["localhost:8080", "https://a.example.com:8443/x", "b.example.com"], policy=H1)
    assert A["httpx"].stdin(c, None) == "a.example.com:8443\nb.example.com\nlocalhost:8080\n"
    args = A["httpx"].build_args(c, None)
    assert ["-H", "X-HackerOne-Research: idris4hack"] == args[-2:]
    assert "-fr" not in args and args[args.index("-rl") + 1] == "2"
    row = {"url": "https://example.com", "status_code": 301, "title": "Home", "tech": ["Nginx"], "location": "https://evil.com/"}
    item = A["httpx"].parse(c, json.dumps(row), "", None)[0]
    assert item["redirect"]["allowed"] is False and item["technologies"] == ["Nginx"]


def test_nmap_safe_flags_and_xml(ctx):
    c = ctx()
    args = A["nmap"].build_args(c, "example.com")
    assert "-sT" in args and "--top-ports" in args and "-oX" in args
    assert not any(a.startswith(("--script", "-O", "-A", "-sS")) for a in args)
    xml = """<?xml version="1.0"?><nmaprun><host><hostnames><hostname name="example.com"/></hostnames>
    <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.25"/></port>
    <port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>"""
    assert A["nmap"].parse(c, xml, "", "example.com") == [{
        "type": "port", "asset": "example.com", "port": 443, "protocol": "tcp",
        "service": "https", "product": "nginx", "version": "1.25"}]
    with pytest.raises(ValueError):
        A["nmap"].parse(c, '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>', "", "example.com")


def test_naabu_connect_scan(ctx):
    c = ctx(targets=["a.example.com", "b.example.com"])
    args = A["naabu"].build_args(c, None)
    assert args[:2] == ["-host", "a.example.com,b.example.com"] and args[args.index("-scan-type") + 1] == "c"
    rows = '{"host":"a.example.com","ip":"1.1.1.1","port":443}\n{"ip":"1.1.1.2","port":{"Port":80}}'
    assert [i["port"] for i in A["naabu"].parse(c, rows, "", None)] == [443, 80]


def test_katana_stays_on_fqdn(ctx):
    c = ctx(policy=H1)
    args = A["katana"].build_args(c, "https://example.com")
    assert args[args.index("-fs") + 1] == "fqdn" and "-H" in args
    row = {"request": {"endpoint": "https://example.com/login", "method": "GET"}, "response": {"status_code": 200}}
    assert A["katana"].parse(c, json.dumps(row), "", "https://example.com")[0]["asset"] == "https://example.com/login"


def test_whatweb_aggression_one_and_log_parse(ctx):
    c = ctx(policy={**H1, "user_agent": "UA/1"})
    args = A["whatweb"].build_args(c, "https://example.com")
    assert args[:2] == ["-a", "1"] and "--header" in args and "-U" in args
    log = A["whatweb"]._log(c, "https://example.com")
    log.write_text(json.dumps([{"target": "https://example.com", "http_status": 200,
                                "plugins": {"nginx": {"version": ["1.25"]}, "HTML5": {}}}]))
    item = A["whatweb"].parse(c, "", "", "https://example.com")[0]
    assert item["technologies"] == {"nginx": "1.25", "HTML5": ""}


def test_tlsx_sans_become_hosts(ctx):
    c = ctx()
    row = {"host": "example.com", "port": "443", "tls_version": "tls13", "subject_an": ["*.example.com", "other.net"], "expired": False}
    items = A["tlsx"].parse(c, json.dumps(row), "", None)
    assert items[0]["type"] == "tls"
    assert {i["asset"] for i in items[1:]} == {"example.com", "other.net"}


def test_cloudlist_requires_provider_config(ctx, settings, tmp_path):
    ok, message = A["cloudlist"].config_status({"tools": {"cloudlist": {"provider_config": str(tmp_path / "none.yaml")}}})
    assert not ok and "Provider config" in message
    c = ctx()
    items = A["cloudlist"].parse(c, '{"dns_name":"app.example.com","provider":"aws"}', "", None)
    assert items == [{"type": "cloud_asset", "asset": "app.example.com", "provider": "aws"}]

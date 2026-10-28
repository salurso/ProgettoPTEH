import sys
import os
import json
import tempfile
import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

for m in [
    "attack-executor",
    "target-recon-agent",
    "vuln-hypothesis-generator",
    "exploit-plan-designer",
    "reporting-engine",
    "core_shared",
]:
    p = os.path.join(ROOT, m)
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)


# ─────────────────────────────────────────────
# UNIT TEST — SafetyValidator
# ─────────────────────────────────────────────

class TestSafetyValidator:
    def setup_method(self):
        import logging
        from executor import SafetyValidator
        self.v = SafetyValidator(logging.getLogger("test"))

    def test_blocca_rm_rf(self):
        ok, reason = self.v.validate("bash", "rm -rf /")
        assert not ok

    def test_blocca_fork_bomb(self):
        ok, reason = self.v.validate("python", ":(){:|:&};:")
        assert not ok

    def test_blocca_modulo_msf_non_approvato(self):
        ok, reason = self.v.validate("metasploit", "", "exploit/windows/smb/ms17_010_eternalblue")
        assert not ok
        assert "non approvato" in reason

    def test_permette_modulo_msf_approvato(self):
        ok, _ = self.v.validate("metasploit", "", "auxiliary/scanner/portscan/tcp")
        assert ok

    def test_permette_nmap_normale(self):
        ok, _ = self.v.validate("nmap", "-sV -T4 192.168.1.1")
        assert ok

    def test_blocca_ip_pubblico_in_sandbox(self):
        os.environ["SANDBOX_MODE"] = "true"
        ok, reason = self.v.validate("nmap", "-sV 8.8.8.8")
        assert not ok
        assert "pubblico" in reason

    def test_permette_ip_privato_in_sandbox(self):
        os.environ["SANDBOX_MODE"] = "true"
        ok, _ = self.v.validate("nmap", "-sV 192.168.1.50")
        assert ok


# ─────────────────────────────────────────────
# UNIT TEST — TargetWhitelist
# ─────────────────────────────────────────────

class TestTargetWhitelist:
    def setup_method(self):
        os.environ["TARGET_WHITELIST"] = "192.168.0.0/16,10.0.0.0/8"
        from executor import TargetWhitelist
        self.wl = TargetWhitelist()

    def test_ip_in_whitelist(self):
        assert self.wl.is_allowed("192.168.1.50") is True

    def test_ip_non_in_whitelist(self):
        assert self.wl.is_allowed("8.8.8.8") is False

    def test_ip_10_in_whitelist(self):
        assert self.wl.is_allowed("10.0.0.1") is True

    def test_loopback_non_in_whitelist(self):
        assert self.wl.is_allowed("127.0.0.1") is False


# ─────────────────────────────────────────────
# UNIT TEST — ParseLLMResponse (recon)
# ─────────────────────────────────────────────

class TestParseLLMResponse:
    def setup_method(self):
        from recon import parse_llm_response
        self.parse = parse_llm_response

    def test_json_diretto(self):
        raw = '{"strategy_description": "test", "tools_to_use": []}'
        result = self.parse(raw)
        assert result is not None
        assert result["strategy_description"] == "test"

    def test_json_con_testo_prima(self):
        raw = 'Ecco la strategia: {"strategy_description": "test", "tools_to_use": []}'
        result = self.parse(raw)
        assert result is not None

    def test_json_in_backtick(self):
        raw = '```json\n{"strategy_description": "test", "tools_to_use": []}\n```'
        result = self.parse(raw)
        assert result is not None

    def test_json_malformato_restituisce_none(self):
        raw = "Questa non e una risposta JSON valida"
        result = self.parse(raw)
        assert result is None

    def test_stringa_vuota(self):
        result = self.parse("")
        assert result is None


# ─────────────────────────────────────────────
# UNIT TEST — NVDCache
# ─────────────────────────────────────────────

class TestNVDCache:
    def setup_method(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        from nvd_client import NVDCache
        self.cache = NVDCache(self.tmp)

    def teardown_method(self):
        if os.path.exists(self.tmp):
            os.remove(self.tmp)

    def test_cache_miss(self):
        result = self.cache.get("apache::2.4.29", ttl_hours=24)
        assert result is None

    def test_cache_set_e_get(self):
        data = [{"cve_id": "CVE-2019-0211", "severity": "HIGH"}]
        self.cache.set("apache::2.4.29", data)
        result = self.cache.get("apache::2.4.29", ttl_hours=24)
        assert result == data

    def test_cache_scaduta(self):
        import time
        data = [{"cve_id": "CVE-TEST"}]
        self.cache.set("test::1.0", data)
        self.cache.conn.execute(
            "UPDATE nvd_cache SET cached_at = ? WHERE query_key = ?",
            (time.time() - 999999, "test::1.0")
        )
        self.cache.conn.commit()
        result = self.cache.get("test::1.0", ttl_hours=24)
        assert result is None

    def test_cache_stats(self):
        self.cache.set("k1", [])
        self.cache.set("k2", [])
        stats = self.cache.stats()
        assert stats["cached_entries"] == 2


# ─────────────────────────────────────────────
# UNIT TEST — RankVulnerabilities
# ─────────────────────────────────────────────

class TestRankVulnerabilities:
    def setup_method(self):
        from generator import rank_vulnerabilities
        self.rank = rank_vulnerabilities

    def test_critical_prima_di_low(self):
        vulns = [
            {"cve_id": "LOW-1", "severity": "LOW", "cvss_score": 2.0,
             "attack_vector": "LOCAL", "confidence_score": 0.5, "nvd_verified": False},
            {"cve_id": "CRITICAL-1", "severity": "CRITICAL", "cvss_score": 9.8,
             "attack_vector": "NETWORK", "confidence_score": 0.9, "nvd_verified": True},
        ]
        ranked = self.rank(vulns)
        assert ranked[0]["cve_id"] == "CRITICAL-1"
        assert ranked[-1]["cve_id"] == "LOW-1"

    def test_rank_assegnato(self):
        vulns = [
            {"cve_id": "A", "severity": "HIGH", "cvss_score": 7.0,
             "attack_vector": "NETWORK", "confidence_score": 0.7, "nvd_verified": True},
            {"cve_id": "B", "severity": "MEDIUM", "cvss_score": 5.0,
             "attack_vector": "LOCAL", "confidence_score": 0.5, "nvd_verified": False},
        ]
        ranked = self.rank(vulns)
        assert ranked[0]["rank"] == 1
        assert ranked[1]["rank"] == 2

    def test_lista_vuota(self):
        assert self.rank([]) == []


# ─────────────────────────────────────────────
# UNIT TEST — ResolveDependencies
# ─────────────────────────────────────────────

class TestResolveDependencies:
    def setup_method(self):
        from designer import resolve_dependencies, PlaybookStep, Playbook
        self.resolve  = resolve_dependencies
        self.Step     = PlaybookStep
        self.Playbook = Playbook

    def _make_step(self, num, dep=None):
        return self.Step(
            step_number=num, name=f"step_{num}", cve_target="",
            tool="nmap", module=None, args="-sV target",
            purpose="test", expected_outcome="ok",
            depends_on_step=dep, on_success="continue",
            on_failure="skip_to_next", rollback_action=None,
            timeout_seconds=30, tool_available=True
        )

    def test_ordine_senza_dipendenze(self):
        pb = self.Playbook("p1", "test", 0.8, "low",
                           [self._make_step(1), self._make_step(2), self._make_step(3)])
        ordered = self.resolve(pb)
        assert [s.step_number for s in ordered] == [1, 2, 3]

    def test_ordine_con_dipendenze(self):
        pb = self.Playbook("p1", "test", 0.8, "low",
                           [self._make_step(3, dep=1), self._make_step(1), self._make_step(2)])
        ordered = self.resolve(pb)
        nums = [s.step_number for s in ordered]
        assert nums.index(1) < nums.index(3)


# ─────────────────────────────────────────────
# UNIT TEST — ComputeFindingsStats
# ─────────────────────────────────────────────

class TestComputeFindingsStats:
    def setup_method(self):
        from reporter import compute_findings_stats
        self.stats = compute_findings_stats

    def test_conteggio_corretto(self):
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "LOW"},
        ]
        result = self.stats(findings)
        assert result["CRITICAL"] == 2
        assert result["HIGH"]     == 1
        assert result["LOW"]      == 1
        assert result["MEDIUM"]   == 0

    def test_lista_vuota(self):
        result = self.stats([])
        assert all(v == 0 for v in result.values())


# ─────────────────────────────────────────────
# INTEGRATION TEST — Mock LLM
# ─────────────────────────────────────────────

class TestIntegrationMockLLM:
    MOCK_RECON = json.dumps({
        "strategy_description": "Scansione TCP completa",
        "tools_to_use": [
            {"tool": "nmap", "command": "nmap -sT -p 1-1024 192.168.1.50",
             "purpose": "port scan", "timeout_seconds": 60}
        ]
    })

    MOCK_VULN = json.dumps({
        "target_ip": "192.168.1.50",
        "hypotheses": [
            {"service_port": 21, "service_name": "vsftpd",
             "cve_id": "CVE-2011-2523", "description": "Backdoor vsftpd",
             "severity": "CRITICAL", "cvss_score": 10.0,
             "attack_vector": "NETWORK", "confidence_score": 0.95,
             "attack_type": "backdoor"}
        ]
    })

    MOCK_EXPLOIT = json.dumps({
        "target_ip": "192.168.1.50",
        "plans": [{
            "plan_id": "plan_test", "description": "Piano test",
            "success_probability": 0.8, "stealth_level": "low",
            "steps": [{
                "step_number": 1, "name": "scan", "cve_target": "",
                "tool": "nmap", "module": None,
                "args": "-sT 192.168.1.50", "purpose": "scan",
                "expected_outcome": "porte aperte",
                "depends_on_step": None, "on_success": "continue",
                "on_failure": "skip_to_next", "rollback_action": None,
                "timeout_seconds": 60
            }]
        }]
    })

    def test_recon_parsing_pipeline(self):
        from recon import parse_llm_response, validate_commands
        parsed = parse_llm_response(self.MOCK_RECON)
        assert parsed is not None
        assert len(parsed["tools_to_use"]) == 1
        valid = validate_commands(parsed, {"nmap": {"available": True}})
        assert len(valid) == 1

    def test_vuln_parsing_pipeline(self):
        from generator import parse_llm_hypotheses, rank_vulnerabilities
        hypotheses = parse_llm_hypotheses(self.MOCK_VULN)
        assert len(hypotheses) == 1
        assert hypotheses[0]["cve_id"] == "CVE-2011-2523"
        ranked = rank_vulnerabilities(hypotheses)
        assert ranked[0]["rank"] == 1

    def test_exploit_parsing_pipeline(self):
        from designer import parse_llm_response, deserialize_plan, rank_plans
        parsed = parse_llm_response(self.MOCK_EXPLOIT)
        assert parsed is not None
        pb = deserialize_plan(parsed["plans"][0], {"nmap": True})
        assert pb.plan_id == "plan_test"
        ranked = rank_plans([pb])
        assert ranked[0].success_probability == 0.8


# ─────────────────────────────────────────────
# EDGE CASES
# ─────────────────────────────────────────────

class TestEdgeCases:
    def test_target_non_in_whitelist_blocca_tutto(self):
        os.environ["TARGET_WHITELIST"] = "10.0.0.0/8"
        from executor import TargetWhitelist
        wl = TargetWhitelist()
        assert wl.is_allowed("192.168.1.50") is False
        assert wl.is_allowed("172.16.0.1")   is False

    def test_cve_non_trovata_abbassa_confidence(self):
        from generator import validate_hypotheses

        class MockNVD:
            def search_cves(self, service, version):
                return []

        hypotheses = [{
            "cve_id": "CVE-9999-9999", "service_name": "fake_service",
            "severity": "HIGH", "cvss_score": 7.0,
            "attack_vector": "NETWORK", "confidence_score": 0.8,
            "description": "CVE inesistente", "service_port": 9999
        }]
        # Firma: ritorna (validated, unverified, weaknesses). Una CVE non confermata
        # finisce tra le ipotesi NON verificate, con confidence abbassata.
        validated, unverified, weaknesses = validate_hypotheses(hypotheses, MockNVD())
        found = next(v for v in unverified if v["cve_id"] == "CVE-9999-9999")
        assert found["confidence_score"] < 0.8
        assert found["nvd_verified"] is False

    def test_playbook_vuoto_non_crasha(self):
        from designer import rank_plans, Playbook
        empty = Playbook("empty", "vuoto", 0.0, "none", [])
        result = rank_plans([empty])
        assert len(result) == 1

    def test_report_collector_senza_file(self):
        from reporter import ReportCollector
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = ReportCollector(tmpdir)
            data = collector.collect()
            assert "target_ip" in data
            assert "vulnerabilities" in data


# ─────────────────────────────────────────────
# UNIT TEST — Iniezione output tra step (catena multi-stadio)
# ─────────────────────────────────────────────

class TestDependencyInjection:
    def setup_method(self):
        from executor import _inject_dependency_output
        self.inject = _inject_dependency_output

    def test_inietta_porta_e_ip(self):
        dep_out = "Nmap scan report for 192.168.56.4\n80/tcp open  http"
        args = "-u http://{{dep_ip}}:{{dep_port}}"
        result = self.inject(args, dep_out)
        assert result == "-u http://192.168.56.4:80"

    def test_inietta_credenziali(self):
        dep_out = "[21][ftp] login: msfadmin   password: msfadmin"
        args = "ftp -u {{dep_user}} -p {{dep_pass}}"
        result = self.inject(args, dep_out)
        assert result == "ftp -u msfadmin -p msfadmin"

    def test_args_senza_placeholder_invariati(self):
        args = "-sV -T4 192.168.56.4"
        assert self.inject(args, "qualsiasi output") == args


# ─────────────────────────────────────────────
# UNIT TEST — OS fingerprinting nel grafo
# ─────────────────────────────────────────────

class TestOSInGraph:
    def setup_method(self):
        import pytest as _pytest
        _pytest.importorskip("libnmap")  # richiesto solo su ambienti con libnmap
        sys.path.insert(0, os.path.join(ROOT, "attack-surface-mapper"))
        from mapper import AttackSurfaceMapper
        self.Mapper = AttackSurfaceMapper

    def test_nodo_e_query_os(self):
        m = self.Mapper()
        data = [
            {"ip": "192.168.56.4", "port": 21, "protocol": "tcp",
             "service": "ftp", "version": "vsftpd 2.3.4", "state": "open",
             "os": "Linux 2.6.9 - 2.6.33"},
        ]
        m.build_graph(data)
        assert m.get_os("192.168.56.4") == "Linux 2.6.9 - 2.6.33"

    def test_os_unknown_non_crea_nodo(self):
        m = self.Mapper()
        data = [
            {"ip": "10.0.0.1", "port": 22, "protocol": "tcp",
             "service": "ssh", "version": "OpenSSH", "state": "open",
             "os": "unknown"},
        ]
        m.build_graph(data)
        assert m.get_os("10.0.0.1") is None

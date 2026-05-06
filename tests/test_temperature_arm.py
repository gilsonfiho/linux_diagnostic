"""
Testes para Coleta e Análise de Temperatura
=============================================
Valida parsing e análise de temperatura em múltiplas arquiteturas.
Foca em testes de Raspberry Pi (ARM) com /sys/class/thermal.
"""

import pytest
from src.collector.system_collector import CommandResult, SystemData
from src.analyzer.diagnostic_analyzer import DiagnosticAnalyzer, DiagnosticResult, Severity
from src.analyzer.hardware import analyze_temperature, TEMP_WARNING_C, TEMP_CRITICAL_C


def make_result(stdout: str, success: bool = True) -> CommandResult:
    """Helper: cria CommandResult."""
    return CommandResult(
        command="mock",
        stdout=stdout,
        stderr="",
        exit_code=0 if success else 1,
        success=success,
    )


class TestTemperatureParsing:
    """Testes de parsing de temperatura de múltiplas fontes."""

    def test_vcgencmd_raspberry_pi_format(self):
        """Testa parsing de vcgencmd do Raspberry Pi: 'temp=45.0'C'"""
        data = SystemData()
        data.vcgencmd_temp = make_result("temp=45.0'C")
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        assert len(result.issues) == 1
        assert result.issues[0].severity == Severity.INFO
        assert "45.0" in result.issues[0].title
        assert "normal" in result.issues[0].title.lower()

    def test_sys_thermal_zone_single_format(self):
        """Testa parsing de thermal_zone0 (sysfs): 'thermal_zone0: 45.0°C'"""
        data = SystemData()
        data.vcgencmd_temp = make_result("thermal_zone0: 45.0°C")
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        assert len(result.issues) == 1
        assert result.issues[0].severity == Severity.INFO
        assert "45.0" in result.issues[0].title

    def test_sys_thermal_zones_multiple(self):
        """Testa parsing de múltiplas thermal_zones (x86_64)."""
        data = SystemData()
        data.vcgencmd_temp = make_result(
            "thermal_zone0: 45.0°C\n"
            "thermal_zone1: 48.5°C\n"
            "thermal_zone2: 52.0°C\n"
        )
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        assert len(result.issues) == 1
        # Deve encontrar a máxima (52.0°C)
        assert "52.0" in result.issues[0].title

    def test_sensors_lm_sensors_format(self):
        """Testa parsing de sensors (lm-sensors): '+42.0°C (high = +100.0°C, crit = +100.0°C)'"""
        data = SystemData()
        data.sensors = make_result(
            "coretemp-isa-0000\nAdapter: ISA adapter\nPackage id 0:  +42.0°C  (high = +100.0°C, crit = +100.0°C)"
        )
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        assert len(result.issues) == 1
        assert result.issues[0].severity == Severity.INFO
        assert "42.0" in result.issues[0].title

    def test_temperature_warning_threshold(self):
        """Testa severidade WARNING quando temperatura ≥ TEMP_WARNING_C."""
        data = SystemData()
        data.vcgencmd_temp = make_result(f"thermal_zone0: {TEMP_WARNING_C:.1f}°C")
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        assert len(result.issues) == 1
        assert result.issues[0].severity == Severity.WARNING
        assert "elevada" in result.issues[0].title.lower() or "high" in result.issues[0].title.lower()

    def test_temperature_critical_threshold(self):
        """Testa severidade CRITICAL quando temperatura ≥ TEMP_CRITICAL_C."""
        data = SystemData()
        data.vcgencmd_temp = make_result(f"thermal_zone0: {TEMP_CRITICAL_C:.1f}°C")
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        assert len(result.issues) == 1
        assert result.issues[0].severity == Severity.CRITICAL
        assert "crítica" in result.issues[0].title.lower() or "critical" in result.issues[0].title.lower()

    def test_temperature_mixed_sources(self):
        """Testa que temperatura de múltiplas fontes é agregada e máxima é reportada."""
        data = SystemData()
        data.sensors = make_result("+35.0°C (high = +100.0°C)")
        data.vcgencmd_temp = make_result("thermal_zone0: 52.0°C\nthermal_zone1: 48.0°C")
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        assert len(result.issues) == 1
        # Máxima é 52.0°C
        assert "52.0" in result.issues[0].title

    def test_temperature_not_available(self):
        """Testa que issue INFO é criada quando nenhuma temperatura disponível."""
        data = SystemData()
        # Não popula sensors nem vcgencmd_temp
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        assert len(result.issues) == 1
        assert result.issues[0].severity == Severity.INFO
        # Aceita português e inglês
        title_lower = result.issues[0].title.lower()
        assert ("não disponível" in title_lower or "disponíveis" in title_lower 
                or "not available" in title_lower)

    def test_temperature_invalid_values_ignored(self):
        """Testa que valores fora da faixa (0-150°C) são ignorados."""
        data = SystemData()
        # Mistura valores válidos com inválidos
        data.vcgencmd_temp = make_result(
            "thermal_zone0: -10.0°C\n"  # Inválido (negativo)
            "thermal_zone1: 200.0°C\n"   # Inválido (> 150)
            "thermal_zone2: 45.0°C\n"    # Válido
        )
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        assert len(result.issues) == 1
        # Deve pegar apenas 45.0°C
        assert "45.0" in result.issues[0].title
        assert result.issues[0].severity == Severity.INFO

    def test_temperature_integer_millicelsius(self):
        """
        Testa parsing de valores inteiros em milicélsius como viriam de /sys/class/thermal bruto.
        Ex: 45000 milicélsius = 45.0°C
        
        Nota: Este é um test de fallback. Em produção, o comando shell converte,
        mas este teste valida que se valores brutos chegarem, não quebram.
        """
        data = SystemData()
        # Se por algum motivo valores em milicélsius chegarem ao parser
        data.vcgencmd_temp = make_result("45000")
        result = DiagnosticResult()
        
        # O parser atual extrai \d+ antes de °C, então 45000 não seria extraído
        # Este é um teste que documenta esse comportamento
        analyze_temperature(data, result)
        
        # Sem o símbolo °C ou °, o valor não é extraído
        # Isso está OK porque o comando shell deve normalizar antes
        assert len(result.issues) == 1
        assert result.issues[0].severity == Severity.INFO


class TestTemperatureAnalyzerIntegration:
    """Testes de integração com DiagnosticAnalyzer."""

    def test_analyzer_includes_temperature_analysis(self):
        """Testa que DiagnosticAnalyzer inclui análise de temperatura."""
        data = SystemData()
        data.hostname = make_result("rpi-test")
        data.os_info = make_result('PRETTY_NAME="Raspbian GNU/Linux 11"')
        data.kernel = make_result("Linux rpi 5.10.92-v7+ #1514 armv7l")
        data.uptime = make_result(" 14:23:01 up 2 days, load average: 0.12, 0.15, 0.18")
        data.load_average = make_result("0.12 0.15 0.18 1/85 1234")
        data.cpu_info = make_result("4")
        data.memory = make_result("Mem: total 1000 used 500 free 500")
        data.disk_usage = make_result("/ 8G 4G 4G 50% /")
        data.vcgencmd_temp = make_result("temp=45.2'C")  # RPi format
        
        analyzer = DiagnosticAnalyzer()
        result = analyzer.analyze(data)
        
        # Verifica que temperatura foi analisada
        temp_issues = [i for i in result.issues if i.category == "Temperatura"]
        assert len(temp_issues) == 1
        assert "45.2" in temp_issues[0].title

    def test_analyzer_arm_multi_zone(self):
        """Testa análise de x86_64 com múltiplas thermal_zones."""
        data = SystemData()
        data.hostname = make_result("server-x86")
        data.os_info = make_result('PRETTY_NAME="Ubuntu 22.04 LTS"')
        data.kernel = make_result("Linux server 5.15.0 #1 x86_64")
        data.uptime = make_result(" 14:23:01 up 1 day")
        data.load_average = make_result("0.5 0.5 0.5 2/256 5000")
        data.cpu_info = make_result("8")
        data.memory = make_result("Mem: total 32000 used 16000 free 16000")
        data.disk_usage = make_result("/ 200G 100G 100G 50% /")
        data.vcgencmd_temp = make_result(
            "thermal_zone0: 48.0°C\n"
            "thermal_zone1: 52.0°C\n"
            "thermal_zone2: 50.0°C\n"
        )
        
        analyzer = DiagnosticAnalyzer()
        result = analyzer.analyze(data)
        
        temp_issues = [i for i in result.issues if i.category == "Temperatura"]
        assert len(temp_issues) == 1
        assert "52.0" in temp_issues[0].title  # Máxima


class TestTemperatureRecommendations:
    """Testes de recomendações para cada nível de severidade."""

    def test_critical_temperature_recommendation(self):
        """Testa que recomendação CRITICAL menciona ações urgentes."""
        data = SystemData()
        data.vcgencmd_temp = make_result(f"thermal_zone0: {TEMP_CRITICAL_C + 5}°C")
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        issue = result.issues[0]
        assert issue.severity == Severity.CRITICAL
        # Recomendação deve mencionar ações urgentes
        assert any(word in issue.recommendation.lower() 
                  for word in ["imediata", "immediate", "urgente", "urgent", "ação", "action"])

    def test_warning_temperature_recommendation(self):
        """Testa que recomendação WARNING menciona monitoramento."""
        data = SystemData()
        data.vcgencmd_temp = make_result(f"thermal_zone0: {TEMP_WARNING_C + 2}°C")
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        issue = result.issues[0]
        assert issue.severity == Severity.WARNING
        # Recomendação deve mencionar monitoramento
        assert any(word in issue.recommendation.lower() 
                  for word in ["monitore", "monitor", "prevent", "preventiv"])

    def test_normal_temperature_recommendation(self):
        """Testa que recomendação INFO diz que sem ação necessária."""
        data = SystemData()
        data.vcgencmd_temp = make_result("thermal_zone0: 35.0°C")
        result = DiagnosticResult()
        
        analyze_temperature(data, result)
        
        issue = result.issues[0]
        assert issue.severity == Severity.INFO
        assert any(word in issue.recommendation.lower() 
                  for word in ["sem ação", "no action", "necessária", "required", "normal"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

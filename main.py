import sys
import textwrap
from scanner.ai.interpreter import AIInterpreter
from scanner.core.scanner import Scanner
from scanner.reports import ReportExporter
from scanner.modules.a03_command_injection import run_command_injection
from scanner.modules.a03_sql_injection import run_sql_injection
from scanner.modules.a03_xss import run_xss
from scanner.modules.a07_brute_force import run_brute_force
from scanner.utils.dvwa import create_dvwa_session

# Configuração de codificação UTF-8 para garantir a correta renderização de acentos no terminal Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass


# Configurações do ambiente de teste (DVWA)
base_url = "http://192.168.100.165"
username = "admin"
password = "password"
security_level = "medium"

# Wordlist para testes de força bruta (A07)
passwords = [
    "123456",
    "admin123",
    "qwerty",
    "password"
]

print("=" * 60)
print("                    SECURESCAN INICIADO                     ")
print("=" * 60)

# 1. Autenticação centralizada e gestão de sessão no alvo
try:
    print(f"[*] Conectando e autenticando no DVWA ({base_url})...")
    shared_session = create_dvwa_session(
        base_url=base_url,
        username=username,
        password=password,
        security_level=security_level
    )
    print(f"[+] Sessão iniciada com sucesso. Nível de segurança: {security_level.upper()}\n")
except Exception as e:
    print(f"\n[-] Erro ao conectar com o alvo ({base_url}): {e}")
    print("[-] DICA: Certifique-se de que a VM Ubuntu com o container Docker do DVWA está ligada.")
    print("\n" + "=" * 60)
    print("              SCAN INTERROMPIDO (ALVO INACESSÍVEL)          ")
    print("=" * 60)
    sys.exit(1)

# 2. Inicialização do orquestrador
scanner = Scanner()

# 3. Registro dos módulos de teste (OWASP Top 10)
scanner.register_module(run_brute_force)
scanner.register_module(run_sql_injection)
scanner.register_module(run_xss)
scanner.register_module(run_command_injection)

# 4. Execução dos testes determinísticos
findings = scanner.run(
    base_url=base_url,
    username=username,
    passwords=passwords,
    session=shared_session
)

# 5. Apresentação estruturada dos resultados (Findings)
print("\n" + "=" * 70)
print("                    RELATÓRIO DE VULNERABILIDADES               ")
print("=" * 70)

if not findings:
    print("\nNenhum achado gerado durante o scan.")
else:
    for index, finding in enumerate(findings, start=1):
        print("\n" + "-" * 70)
        print(f" Achado #{index}: {finding.test.upper()} [{finding.severity.upper()}]")
        print("-" * 70)
        print(f" Categoria OWASP:  {finding.category} - {finding.name}")
        print(f" Status:           {finding.status.upper()}")
        print(f" Severidade:       {finding.severity.upper()}")
        
        print("\n [Evidência Técnica]:")
        wrapped_evidence = textwrap.fill(finding.evidence, width=68, initial_indent="   ", subsequent_indent="   ")
        print(wrapped_evidence)
        
        print("\n [Recomendação de Defesa]:")
        wrapped_rec = textwrap.fill(finding.recommendation, width=68, initial_indent="   ", subsequent_indent="   ")
        print(wrapped_rec)
    print("\n" + "-" * 70)

# 6. Camada de Inteligência Artificial: Interpretação e Contextualização
print("\n" + "=" * 70)
print("          INTERPRETAÇÃO E ANÁLISE EXECUTIVA (IA)            ")
print("=" * 70)
print("\n[*] Processando achados através da camada de Inteligência Artificial...\n")

ai_interpreter = AIInterpreter()
ai_report = ai_interpreter.interpret_findings(findings)

print(ai_report)

# 7. Exportação Automatizada de Relatórios (HTML, Markdown e JSON)
print("\n" + "=" * 70)
print("                 EXPORTAÇÃO DE RELATÓRIOS                   ")
print("=" * 70)
print("[*] Gerando relatórios consolidados nos formatos HTML, Markdown e JSON...")

exporter = ReportExporter(output_dir="reports")
exported_files = exporter.export_all(
    target_url=base_url,
    security_level=security_level,
    findings=findings,
    ai_report=ai_report
)

print(f"\n[+] Relatório HTML (Visual/Interativo): {exported_files['html']}")
print(f"[+] Relatório Markdown (Documentação):  {exported_files['markdown']}")
print(f"[+] Relatório JSON (Dados Estruturados): {exported_files['json']}")
print("\n[i] DICA: Abra o arquivo .html no navegador ou pressione Ctrl+P para salvar em PDF!")

print("\n" + "=" * 70)
print("                        SCAN CONCLUÍDO                      ")
print("=" * 70)
import json
import os
import sys
import mimetypes
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

# Assegura que o diretório raiz está no PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.core.scanner import Scanner
from scanner.modules.a07_brute_force import run_brute_force
from scanner.modules.a03_sql_injection import run_sql_injection
from scanner.modules.a03_xss import run_xss
from scanner.modules.a03_command_injection import run_command_injection
from scanner.utils.dvwa import create_dvwa_session
from scanner.ai.interpreter import AIInterpreter


# Mapeamento MIME explícito para evitar problemas de registro no Windows
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("text/html", ".html")


class SecureScanAPIHandler(SimpleHTTPRequestHandler):
    """
    Servidor HTTP leve para o SecureScan.
    - Serve a interface web construída em React a partir de frontend/dist/
    - Expõe a rota /api/scan para disparar varreduras reais contra a aplicação alvo
    - Suporta CORS para desenvolvimento local
    """

    def __init__(self, *args, **kwargs):
        # Serve os arquivos compilados do React na pasta frontend/dist se existirem
        dist_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "dist")
        if os.path.exists(dist_dir):
            super().__init__(*args, directory=dist_dir, **kwargs)
        else:
            super().__init__(*args, **kwargs)

    def end_headers(self):
        # Habilita CORS para requisições do frontend
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        parsed_url = urlparse(self.path)

        if parsed_url.path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")
            
            try:
                body = json.loads(post_data) if post_data else {}
            except Exception:
                body = {}

            target_url = body.get("target_url", "http://192.168.100.165").rstrip("/")
            security_level = body.get("security_level", "medium")

            print(f"\n[API] Requisição de scan recebida para {target_url} (Nível: {security_level.upper()})")

            try:
                # 1. Autenticação centralizada no DVWA
                shared_session = create_dvwa_session(
                    base_url=target_url,
                    username="admin",
                    password="password",
                    security_level=security_level
                )

                # 2. Inicialização do orquestrador
                scanner = Scanner()
                scanner.register_module(run_brute_force)
                scanner.register_module(run_sql_injection)
                scanner.register_module(run_xss)
                scanner.register_module(run_command_injection)

                # 3. Execução dos testes
                findings = scanner.run(
                    base_url=target_url,
                    username="admin",
                    passwords=["123456", "admin123", "qwerty", "password"],
                    session=shared_session
                )

                # 4. Camada de Inteligência Artificial
                ai_interpreter = AIInterpreter()
                ai_report = ai_interpreter.interpret_findings(findings)

                # 5. Montagem da resposta compatível com a interface TypeScript
                response_data = {
                    "targetUrl": target_url,
                    "securityLevel": security_level,
                    "timestamp": "Agora mesmo",
                    "durationSeconds": 6,
                    "summary": {
                        "total": len(findings),
                        "critical": sum(1 for f in findings if f.severity.lower() == "critical"),
                        "high": sum(1 for f in findings if f.severity.lower() == "high"),
                        "medium": sum(1 for f in findings if f.severity.lower() == "medium"),
                        "low": sum(1 for f in findings if f.severity.lower() == "low"),
                        "safe": 0
                    },
                    "findings": [
                        {
                            "id": f"FIND-{idx:03d}",
                            "category": f.category,
                            "name": f.name,
                            "test": f.test,
                            "status": f.status,
                            "severity": f.severity,
                            "evidence": f.evidence,
                            "recommendation": f.recommendation
                        }
                        for idx, f in enumerate(findings, start=1)
                    ],
                    "aiExecutiveReport": ai_report
                }

                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps(response_data, ensure_ascii=False).encode("utf-8"))

            except Exception as err:
                print(f"[API ERROR] Erro durante o scan: {err}")
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(err)}, ensure_ascii=False).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()


def run_server(port=5000):
    server_address = ("", port)
    httpd = HTTPServer(server_address, SecureScanAPIHandler)
    print("=" * 60)
    print(f"      SECURESCAN WEB SERVER INICIADO EM http://localhost:{port}")
    print("=" * 60)
    print(f"[*] Acesse http://localhost:{port} no seu navegador para usar a interface!")
    print("[*] Pressione Ctrl+C para encerrar o servidor.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")


if __name__ == "__main__":
    run_server()

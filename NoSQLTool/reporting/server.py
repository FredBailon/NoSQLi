from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Optional
from urllib.parse import unquote, urlparse

from .models import ReportDocument
from .repository import ReportRepository


class ReportHttpServer:
    def __init__(
        self,
        repository: ReportRepository,
        host: str = "0.0.0.0",
        port: int = 8000,
        public_url: Optional[str] = None,
    ) -> None:
        self._repository = repository
        self._host = host
        self._port = port
        self._public_url = public_url or self._build_default_public_url(host, port)
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[Thread] = None

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def public_url(self) -> str:
        return self._public_url.rstrip("/")

    @property
    def is_running(self) -> bool:
        return self._httpd is not None

    def start(self) -> None:
        if self._httpd is not None:
            return

        handler_class = self._make_handler()
        self._httpd = ThreadingHTTPServer((self._host, self._port), handler_class)
        self._thread = Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is None:
            return

        self._httpd.shutdown()
        self._httpd.server_close()
        self._httpd = None
        self._thread = None

    def url_for(self, report: ReportDocument) -> str:
        return f"{self.public_url}{report.route}"

    @staticmethod
    def _build_default_public_url(host: str, port: int) -> str:
        public_host = "localhost" if host in {"0.0.0.0", "::"} else host
        return f"http://{public_host}:{port}"

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        repository = self._repository

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/") or "/"

                if path in {"/", "/reports"}:
                    self._write_html(200, self._render_index())
                    return

                if path.startswith("/reports/"):
                    self._handle_report(path)
                    return

                self._write_html(404, self._render_not_found())

            def log_message(self, format: str, *args: object) -> None:
                return

            def _handle_report(self, path: str) -> None:
                parts = [part for part in path.split("/") if part]
                if len(parts) not in {2, 3} or parts[0] != "reports":
                    self._write_html(404, self._render_not_found())
                    return

                report_id = unquote(parts[1])
                report = repository.get(report_id)
                if report is None:
                    self._write_html(404, self._render_not_found())
                    return

                if len(parts) == 2:
                    self._write_html(200, self._render_report(report))
                    return

                if parts[2] == "raw":
                    self._write_report(report)
                    return

                self._write_html(404, self._render_not_found())

            def _write_report(self, report: ReportDocument) -> None:
                content = report.content.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", report.content_type)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header(
                    "Content-Disposition",
                    f'inline; filename="{report.filename}"',
                )
                self.end_headers()
                self.wfile.write(content)

            def _write_html(self, status: int, body: str) -> None:
                content = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(content)

            def _render_index(self) -> str:
                reports = repository.list_all()
                items = "\n".join(
                    (
                        "<li>"
                        f"<a href=\"{report.route}\">{escape(report.title)}</a>"
                        f" <small>{escape(report.kind)} / {escape(report.format)}"
                        f" / {escape(report.created_at.isoformat(timespec='seconds'))}"
                        "</small>"
                        "</li>"
                    )
                    for report in reports
                )
                if not items:
                    items = "<li>No hay reportes en memoria.</li>"

                return self._page(
                    "Reportes NoSQLTool",
                    (
                        "<h1>Reportes NoSQLTool</h1>"
                        "<p>Los reportes se conservan solo en memoria mientras "
                        "el CLI esta en ejecucion.</p>"
                        f"<ul>{items}</ul>"
                    ),
                )

            def _render_report(self, report: ReportDocument) -> str:
                raw_url = f"{report.route}/raw"
                return self._page(
                    report.title,
                    (
                        f"<p><a href=\"/reports\">Volver</a> | "
                        f"<a href=\"{raw_url}\">Ver contenido raw</a></p>"
                        f"<h1>{escape(report.title)}</h1>"
                        f"<p><strong>Formato:</strong> {escape(report.format)} "
                        f"<strong>Creado:</strong> "
                        f"{escape(report.created_at.isoformat(timespec='seconds'))}</p>"
                        f"<pre>{escape(report.content)}</pre>"
                    ),
                )

            def _render_not_found(self) -> str:
                return self._page(
                    "No encontrado",
                    "<h1>No encontrado</h1><p>El reporte solicitado no existe.</p>",
                )

            def _page(self, title: str, body: str) -> str:
                return (
                    "<!doctype html>"
                    "<html lang=\"es\">"
                    "<head>"
                    "<meta charset=\"utf-8\">"
                    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                    f"<title>{escape(title)}</title>"
                    "<style>"
                    "body{font-family:Arial,sans-serif;max-width:1100px;margin:32px auto;"
                    "padding:0 16px;line-height:1.45;color:#1f2933}"
                    "a{color:#075985}"
                    "pre{white-space:pre-wrap;word-break:break-word;background:#f6f8fa;"
                    "border:1px solid #d0d7de;border-radius:6px;padding:16px;overflow:auto}"
                    "small{color:#52616b}"
                    "</style>"
                    "</head>"
                    f"<body>{body}</body>"
                    "</html>"
                )

        return Handler

import contextlib
import re
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin

import requests


class FileUploadParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.file_forms = []
        self.current_form = None
        self.has_file_input = False

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == "form":
            self.current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "get").lower(),
                "enctype": attr_dict.get("enctype", ""),
                "file_inputs": [],
            }
            self.has_file_input = False
        elif self.current_form is not None and tag == "input":
            input_type = attr_dict.get("type", "text").lower()
            input_name = attr_dict.get("name", "")
            if input_type == "file":
                self.has_file_input = True
                self.current_form["file_inputs"].append({
                    "name": input_name,
                    "accept": attr_dict.get("accept", ""),
                })

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            if self.has_file_input:
                self.file_forms.append(self.current_form)
            self.current_form = None
            self.has_file_input = False


DANGEROUS_EXTENSIONS = [
    ".php", ".phtml", ".pht", ".php5", ".php7", ".php8",
    ".asp", ".aspx", ".ashx", ".asmx",
    ".jsp", ".jspx",
    ".py", ".rb", ".pl", ".cgi",
    ".exe", ".dll", ".so",
    ".shtml", ".stm", ".shtm",
    ".war", ".ear",
]

BYPASS_PATTERNS = [
    ".php.jpg", ".php.png", ".php.gif",
    ".php%00.jpg", ".php .jpg",
    ".PhP", ".pHP5", ".PHP",
    ".php/.", ".pHp",
]


def check_file_upload(url: str, html_content: str = "",
                      session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    if not html_content:
        try:
            r = client.get(url, timeout=8)
            html_content = r.text
        except requests.RequestException:
            return results

    parser = FileUploadParser()
    with contextlib.suppress(Exception):
        parser.feed(html_content)

    file_forms = parser.file_forms
    for form in file_forms:
        action = urljoin(url, form["action"])
        for fi in form["file_inputs"]:
            accept = fi.get("accept", "")
            if accept:
                results.append({
                    "vuln": "Formulario de Subida de Archivos Detectado",
                    "risk": "Bajo",
                    "detail": f"Formulario con input file '{fi['name']}' en '{action}'. Accept: '{accept}'. Metodo: {form['method']}. Verificar validacion de tipo/extensión en servidor."
                })
            else:
                results.append({
                    "vuln": "Formulario de Subida de Archivos sin Restriccion Visible",
                    "risk": "Medio",
                    "detail": f"Formulario con input file '{fi['name']}' en '{action}' sin atributo 'accept'. Metodo: {form['method']}. Verificar validacion de extensiones en servidor."
                })

    upload_endpoints = re.findall(
        r'(?:/upload|/uploads|/file/upload|/api/upload|/api/files|/media/upload)',
        html_content, re.IGNORECASE,
    )
    for ep in set(upload_endpoints):
        results.append({
            "vuln": "Endpoint de Subida de Archivos Encontrado",
            "risk": "Bajo",
            "detail": f"Referencia a endpoint de subida en codigo: '{ep}'. Verificar que tenga validacion de extensiones, antivirus y limite de tamano."
        })

    return results

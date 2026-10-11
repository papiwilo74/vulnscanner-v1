"""
Módulo CLI de OmniBreach: Parser de argumentos y Despachador de Comandos.
"""
from cli.dispatch import dispatch_cli
from cli.parser import build_cli_parser

__all__ = ["build_cli_parser", "dispatch_cli"]

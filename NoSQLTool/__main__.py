#!/usr/bin/env python3
"""
Punto de entrada del proyecto NoSQL Tool.

Permite ejecutar en dos modos:
1. CLI interactivo: python -m NoSQLTool
2. Servidor de reportes: python -m NoSQLTool --server
"""

import sys
import os


def main():
    """Punto de entrada principal."""
    
    # Verificar argumentos
    if len(sys.argv) > 1 and sys.argv[1] == "--server":
        # Ejecutar servidor de reportes
        from .reports.server import main as run_server
        run_server()
    else:
        # Ejecutar CLI interactivo
        from .cli import main as run_cli
        run_cli()


if __name__ == "__main__":
    main()

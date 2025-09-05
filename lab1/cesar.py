#!/usr/bin/env python3
from typing import Iterable
import argparse

def cesar(texto: str, k: int) -> str:
    
    k %= 26  # normaliza k para manejar negativos o valores grandes
    res: list[str] = []
    a = ord('a')
    for ch in texto:
        if 'a' <= ch <= 'z':
            desplazada = (ord(ch) - a + k) % 26 + a
            res.append(chr(desplazada))
        else:
            res.append(ch)
    return "".join(res)

def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Cifra texto usando el algoritmo César (solo letras a-z, mod 26)."
    )
    parser.add_argument("k", type=int, help="desplazamiento (puede ser negativo o grande)")
    parser.add_argument(
        "texto",
        nargs="+",
        help="texto a cifrar (si tiene espacios, escríbelo entre comillas)"
    )
    args = parser.parse_args(argv)
    texto = " ".join(args.texto)
    print(cesar(texto, args.k))

if __name__ == "__main__":
    main()

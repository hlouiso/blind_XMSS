#!/usr/bin/env python3
import argparse, hashlib, os, re, sys

SHA256_LEN = 32
LAMPORT_LEN = 512  # w=2 => 512 "chaînes" de longueur 1 (sigma ou H(sigma))

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def read_root_hex(path: str) -> bytes:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        txt = fh.read()
    m = re.search(r"\b([0-9A-Fa-f]{64})\b", txt)
    if not m:
        raise ValueError(f"Impossible de trouver une racine (64 hex) dans {path}")
    return bytes.fromhex(m.group(1))

def parse_signature_file(sig_path: str):
    with open(sig_path, "r", encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh.readlines()]
    # retire lignes vides
    nz = [ln for ln in lines if ln != ""]
    if len(nz) < 1 + LAMPORT_LEN:
        raise ValueError("Fichier signature trop court ou mal formaté")

    try:
        leaf_idx = int(nz[0], 10)
    except Exception as e:
        raise ValueError(f"leaf_idx invalide en 1ʳᵉ ligne: {e}")

    sig_elems_hex = nz[1:1+LAMPORT_LEN]
    if any(len(x) != 64 or not re.fullmatch(r"[0-9A-Fa-f]{64}", x) for x in sig_elems_hex):
        raise ValueError("Éléments de signature: chaque ligne doit être 64 hex")

    sig_elems = [bytes.fromhex(x) for x in sig_elems_hex]
    auth_path_hex = nz[1+LAMPORT_LEN:]
    if len(auth_path_hex) == 0:
        raise ValueError("Chemin d’authentification manquant (au moins 1 ligne)")

    if any(len(x) != 64 or not re.fullmatch(r"[0-9A-Fa-f]{64}", x) for x in auth_path_hex):
        raise ValueError("Chemin d’authentification: chaque ligne doit être 64 hex")

    auth_path = [bytes.fromhex(x) for x in auth_path_hex]
    H = len(auth_path)  # hauteur déduite
    return leaf_idx, sig_elems, auth_path, H

def read_message_hex(args) -> bytes:
    if args.msg_hex:
        hx = args.msg_hex.strip()
    elif args.msg_file:
        with open(args.msg_file, "r", encoding="utf-8") as fh:
            hx = fh.read().strip()
    else:
        raise ValueError("Fournis --msg-hex ou --msg-file")
    hx = re.sub(r"\s+", "", hx)
    if not re.fullmatch(r"[0-9A-Fa-f]+", hx or ""):
        raise ValueError("Message: doit être en hex")
    msg = bytes.fromhex(hx)
    if len(msg) != 64:
        raise ValueError(f"Message: attendu 64 octets (128 hex), reçu {len(msg)} octets")
    return msg

def bit_of(msg_bytes: bytes, i: int) -> int:
    # même convention que ton C: bit 0 = MSB du 1er octet
    b = msg_bytes[i // 8]
    return (b >> (7 - (i % 8))) & 1

def compute_leaf_from_sig(sig_elems: list[bytes], msg_bytes: bytes) -> bytes:
    # Vérif WOTS w=2:
    # - si bit==0: on attend sigma  -> verifier avec H(sigma)
    # - si bit==1: on attend H(sigma) -> utiliser tel quel
    v_list = []
    for i in range(LAMPORT_LEN):
        s = sig_elems[i]
        if len(s) != SHA256_LEN:
            raise ValueError("Élément de signature de longueur invalide")
        if bit_of(msg_bytes, i) == 0:
            v_list.append(sha256(s))
        else:
            v_list.append(s)
    concat = b"".join(v_list)  # 512 * 32 = 16384
    return sha256(concat)

def climb_merkle(leaf: bytes, auth_path: list[bytes], leaf_idx: int) -> bytes:
    node = leaf
    idx = leaf_idx
    for sib in auth_path:  # niveau 0 -> H-1
        if len(sib) != SHA256_LEN:
            raise ValueError("Nœud du chemin d’auth de longueur invalide")
        if (idx & 1) == 0:
            parent = sha256(node + sib)   # frère à droite si bit=0
        else:
            parent = sha256(sib + node)   # frère à gauche si bit=1
        node = parent
        idx >>= 1
    return node

def main():
    ap = argparse.ArgumentParser(description="Vérifieur MSS (Lamport/WOTS w=2 + Merkle)")
    ap.add_argument("--sig", required=True, help="chemin vers MSS_signature.txt")
    ap.add_argument("--pub", required=True, help="chemin vers MSS_public_key.txt (contient la racine en hex)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--msg-hex", help="message aveuglé en hex (128 hex, 64 octets)")
    g.add_argument("--msg-file", help="fichier contenant le message aveuglé en hex")
    args = ap.parse_args()

    leaf_idx, sig_elems, auth_path, H = parse_signature_file(args.sig)
    root_expected = read_root_hex(args.pub)
    msg_bytes = read_message_hex(args)

    leaf = compute_leaf_from_sig(sig_elems, msg_bytes)
    root_computed = climb_merkle(leaf, auth_path, leaf_idx)

    ok = (root_computed == root_expected)
    print(f"Hauteur H déduite : {H}")
    print(f"leaf_idx          : {leaf_idx}")
    print(f"Racine attendue   : {root_expected.hex().upper()}")
    print(f"Racine calculée   : {root_computed.hex().upper()}")
    print("SIGNATURE VALIDE" if ok else "SIGNATURE INVALIDE")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()

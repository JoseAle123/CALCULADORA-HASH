    # ================= SHA-384 MANUAL DESDE CERO =================
    
import struct
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import math
import hmac
from Crypto.Hash import MD4
class HashCalculator:
    """
    Calculadora de funciones hash criptográficas
    """
    
    def __init__(self):
        self.algorithms = ['MD5', 'SHA-1', 'SHA-256', 'MD4', 'SHA384', 'HMAC-SHA256']
    
    @staticmethod
    def _left_rotate(n, b, bits=32):
        """Rotación circular a la izquierda (32 bits)"""
        n &= (2**bits - 1)
        return ((n << b) | (n >> (bits - b))) & (2**bits - 1)
    
    @staticmethod
    def _right_rotate(n, b, bits=32):
        """Rotación circular a la derecha (32 bits)"""
        n &= (2**bits - 1)
        return ((n >> b) | (n << (bits - b))) & (2**bits - 1)
    
    @staticmethod
    def _left_rotate_64(n, b, bits=64):
        """Rotación circular a la izquierda (64 bits)"""
        n &= (2**bits - 1)
        return ((n << b) | (n >> (bits - b))) & (2**bits - 1)

    @staticmethod
    def _right_rotate_64(n, b, bits=64):
        b &= 63   # ← IMPORTANTE FIX
        n &= (2**bits - 1)
        return ((n >> b) | (n << (bits - b))) & (2**bits - 1)
    
    @staticmethod
    def _padding_md5_md4(message_bytes):
        """Padding para MD5 y MD4 (Little-Endian)"""
        msg_len = len(message_bytes)
        message_bytes += b'\x80'
        
        while (len(message_bytes) * 8) % 512 != 448:
            message_bytes += b'\x00'
        
        # Longitud en Little-Endian (<Q)
        message_bytes += struct.pack('<Q', msg_len * 8) 
        return message_bytes
    
    @staticmethod
    def _sigma0_512(x):
        """Función de expansión de mensaje sigma_0 (64 bits)"""
        # ROTR^1(x) XOR ROTR^8(x) XOR SHR^7(x)
        r1 = HashCalculator._right_rotate_64(x, 1)
        r8 = HashCalculator._right_rotate_64(x, 8)
        s7 = x >> 7
        return r1 ^ r8 ^ s7
    
    @staticmethod
    def _sigma1_512(x):
        """Función de expansión de mensaje sigma_1 (64 bits)"""
        # ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x)
        r19 = HashCalculator._right_rotate_64(x, 19)
        r61 = HashCalculator._right_rotate_64(x, 61)
        s6 = x >> 6
        return r19 ^ r61 ^ s6
    
    @staticmethod
    def _sum0_512(x):
        """Función de compresión sumatoria Sigma_0 (64 bits)"""
        # ROTR^28(x) XOR ROTR^34(x) XOR ROTR^39(x)
        r28 = HashCalculator._right_rotate_64(x, 28)
        r34 = HashCalculator._right_rotate_64(x, 34)
        r39 = HashCalculator._right_rotate_64(x, 39)
        return r28 ^ r34 ^ r39
        
    @staticmethod
    def _sum1_512(x):
        """Función de compresión sumatoria Sigma_1 (64 bits)"""
        # ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x)
        r14 = HashCalculator._right_rotate_64(x, 14)
        r18 = HashCalculator._right_rotate_64(x, 18)
        r41 = HashCalculator._right_rotate_64(x, 41)
        return r14 ^ r18 ^ r41

    @staticmethod
    def _padding_sha_simple(message_bytes, block_size=64, len_size=8):
        """Padding para SHA-1 y SHA-256 (Big-Endian)"""
        msg_len = len(message_bytes)
        message_bytes += b'\x80'
        
        # 512 bits (64 bytes) - 64 bits (8 bytes) de longitud = 448 bits
        len_in_bytes = block_size - len_size
        
        while len(message_bytes) % block_size != len_in_bytes:
            message_bytes += b'\x00'
        
        # Longitud en Big-Endian (>Q)
        message_bytes += struct.pack('>Q', msg_len * 8) 
        return message_bytes

    @staticmethod
    def _padding_sha512(message_bytes):
        """Padding para SHA-384/512 (Bloque de 128 bytes, longitud de 16 bytes, Big-Endian)"""
        msg_len = len(message_bytes)
        message_bytes += b'\x80'
        
        # 1024 bits (128 bytes) - 128 bits (16 bytes) de longitud = 896 bits
        while len(message_bytes) % 128 != 112:
            message_bytes += b'\x00'
        
        # Longitud en 128 bits (16 bytes), Big-Endian (>QQ)
        message_bytes += struct.pack('>Q', 0)
        message_bytes += struct.pack('>Q', msg_len * 8)
        return message_bytes
    
    # --- Implementaciones ---

    def md5(self, message):
        """Implementación de MD5"""
        T = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
        
        A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
        F = lambda x, y, z: (x & y) | (~x & z)
        G = lambda x, y, z: (x & z) | (y & ~z)
        H = lambda x, y, z: x ^ y ^ z
        I = lambda x, y, z: y ^ (x | ~z)
        
        message_bytes = self._padding_md5_md4(message.encode('utf-8'))
        shifts = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + \
                 [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
        
        for offset in range(0, len(message_bytes), 64):
            block = message_bytes[offset:offset + 64]
            M = list(struct.unpack('<16I', block))
            
            AA, BB, CC, DD = A, B, C, D
            
            for i in range(64):
                if i < 16:
                    f = F(B, C, D) ; g = i
                elif i < 32:
                    f = G(B, C, D) ; g = (5 * i + 1) % 16
                elif i < 48:
                    f = H(B, C, D) ; g = (3 * i + 5) % 16
                else:
                    f = I(B, C, D) ; g = (7 * i) % 16
                
                f = (f + A + T[i] + M[g]) & 0xFFFFFFFF
                A = D; D = C; C = B
                B = (B + self._left_rotate(f, shifts[i])) & 0xFFFFFFFF
            
            A = (A + AA) & 0xFFFFFFFF; B = (B + BB) & 0xFFFFFFFF
            C = (C + CC) & 0xFFFFFFFF; D = (D + DD) & 0xFFFFFFFF
        
        result = struct.pack('<4I', A, B, C, D)
        return result.hex()
    
    def sha1(self, message):
        """Implementación de SHA-1 - CORREGIDO: Uso de padding Big-Endian"""
        h0, h1, h2, h3, h4 = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 
                              0x10325476, 0xC3D2E1F0)
        K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
        
        # CORRECCIÓN: Usar padding Big-Endian
        message_bytes = self._padding_sha_simple(message.encode('utf-8'), block_size=64, len_size=8)
        
        for offset in range(0, len(message_bytes), 64):
            block = message_bytes[offset:offset + 64]
            # SHA-1 siempre usa Big-Endian
            W = list(struct.unpack('>16I', block))
            
            for i in range(16, 80):
                W.append(self._left_rotate(
                    W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1))
            
            a, b, c, d, e = h0, h1, h2, h3, h4
            
            for i in range(80):
                if i < 20:
                    f = (b & c) | (~b & d); k = K[0]
                elif i < 40:
                    f = b ^ c ^ d; k = K[1]
                elif i < 60:
                    f = (b & c) | (b & d) | (c & d); k = K[2]
                else:
                    f = b ^ c ^ d; k = K[3]
                
                temp = (self._left_rotate(a, 5) + f + e + k + W[i]) & 0xFFFFFFFF
                e, d, c, b, a = d, c, self._left_rotate(b, 30), a, temp
            
            h0 = (h0 + a) & 0xFFFFFFFF; h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF; h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF
        
        return ''.join(f'{x:08x}' for x in [h0, h1, h2, h3, h4])
    
    def sha256(self, message):
        """Implementación de SHA-256 (delegada a sha256_bytes)"""
        return self.sha256_bytes(message.encode('utf-8'))

    def sha256_bytes(self, message_bytes):
        """SHA-256 adaptado para recibir bytes (usado por HMAC)"""
        h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        k = [ # ... (k constants omitted for brevity) ...
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        
        # Usar padding Big-Endian
        message_bytes = self._padding_sha_simple(message_bytes, block_size=64, len_size=8)
        
        for offset in range(0, len(message_bytes), 64):
            block = message_bytes[offset:offset + 64]
            w = list(struct.unpack('>16I', block))
            
            for i in range(16, 64):
                s0 = (self._right_rotate(w[i-15], 7) ^ self._right_rotate(w[i-15], 18) ^ (w[i-15] >> 3))
                s1 = (self._right_rotate(w[i-2], 17) ^ self._right_rotate(w[i-2], 19) ^ (w[i-2] >> 10))
                w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)
            
            a, b, c, d, e, f, g, h_var = h
            
            for i in range(64):
                S1 = (self._right_rotate(e, 6) ^ self._right_rotate(e, 11) ^ self._right_rotate(e, 25))
                ch = (e & f) ^ (~e & g)
                temp1 = (h_var + S1 + ch + k[i] + w[i]) & 0xFFFFFFFF
                
                S0 = (self._right_rotate(a, 2) ^ self._right_rotate(a, 13) ^ self._right_rotate(a, 22))
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & 0xFFFFFFFF
                
                h_var, g, f, e = g, f, e, (d + temp1) & 0xFFFFFFFF
                d, c, b, a = c, b, a, (temp1 + temp2) & 0xFFFFFFFF
            
            h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, h_var])]
        
        return ''.join(f'{x:08x}' for x in h)


    def md4(self, message):
        """Implementación de MD4"""
        A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
        
        F = lambda x, y, z: (x & y) | (~x & z)
        G = lambda x, y, z: (x & y) | (x & z) | (y & z)
        H = lambda x, y, z: x ^ y ^ z
        
        message_bytes = self._padding_md5_md4(message.encode('utf-8'))
        
        for offset in range(0, len(message_bytes), 64):
            # ... (Lógica MD4. Se asume correcta) ...
            block = message_bytes[offset:offset + 64]
            M = list(struct.unpack('<16I', block))
            
            AA, BB, CC, DD = A, B, C, D
            
            # Round 1
            indices_r1 = list(range(16))
            shifts_r1 = [3, 7, 11, 19] * 4
            for i in range(16):
                idx = indices_r1[i]
                shift = shifts_r1[i]
                if i % 4 == 0:
                    A = self._left_rotate((A + F(B, C, D) + M[idx]) & 0xFFFFFFFF, shift)
                elif i % 4 == 1:
                    D = self._left_rotate((D + F(A, B, C) + M[idx]) & 0xFFFFFFFF, shift)
                elif i % 4 == 2:
                    C = self._left_rotate((C + F(D, A, B) + M[idx]) & 0xFFFFFFFF, shift)
                else:
                    B = self._left_rotate((B + F(C, D, A) + M[idx]) & 0xFFFFFFFF, shift)
            
            # Round 2
            indices_r2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
            shifts_r2 = [3, 5, 9, 13] * 4
            K2 = 0x5A827999
            for i in range(16):
                idx = indices_r2[i]
                shift = shifts_r2[i]
                if i % 4 == 0:
                    A = self._left_rotate((A + G(B, C, D) + M[idx] + K2) & 0xFFFFFFFF, shift)
                elif i % 4 == 1:
                    D = self._left_rotate((D + G(A, B, C) + M[idx] + K2) & 0xFFFFFFFF, shift)
                elif i % 4 == 2:
                    C = self._left_rotate((C + G(D, A, B) + M[idx] + K2) & 0xFFFFFFFF, shift)
                else:
                    B = self._left_rotate((B + G(C, D, A) + M[idx] + K2) & 0xFFFFFFFF, shift)
            
            # Round 3
            indices_r3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            shifts_r3 = [3, 9, 11, 15] * 4
            K3 = 0x6ED9EBA1
            for i in range(16):
                idx = indices_r3[i]
                shift = shifts_r3[i]
                if i % 4 == 0:
                    A = self._left_rotate((A + H(B, C, D) + M[idx] + K3) & 0xFFFFFFFF, shift)
                elif i % 4 == 1:
                    D = self._left_rotate((D + H(A, B, C) + M[idx] + K3) & 0xFFFFFFFF, shift)
                elif i % 4 == 2:
                    C = self._left_rotate((C + H(D, A, B) + M[idx] + K3) & 0xFFFFFFFF, shift)
                else:
                    B = self._left_rotate((B + H(C, D, A) + M[idx] + K3) & 0xFFFFFFFF, shift)
            
            A = (A + AA) & 0xFFFFFFFF
            B = (B + BB) & 0xFFFFFFFF
            C = (C + CC) & 0xFFFFFFFF
            D = (D + DD) & 0xFFFFFFFF
        
        result = struct.pack('<4I', A, B, C, D)
        return result.hex()

    


    @staticmethod
    def _sha512_padding(message_bytes):
        msg_len = len(message_bytes)
        bit_len = msg_len * 8

        # 1) copy to avoid mutation bugs
        m = bytearray(message_bytes)

        # 2) append 0x80
        m.append(0x80)

        # 3) pad with zeros until length ≡ 112 mod 128
        while (len(m) % 128) != 112:
            m.append(0)

        # 4) append 128-bit length (big endian)
        m += struct.pack('>QQ', 0, bit_len)

        return bytes(m)

    @staticmethod
    def _sha512_sigma0(x):
        return ((HashCalculator._right_rotate_64(x, 1) ^ HashCalculator._right_rotate_64(x, 8) ^ (x >> 7)))

    @staticmethod
    def _sha512_sigma1(x):
        return ((HashCalculator._right_rotate_64(x, 19) ^ HashCalculator._right_rotate_64(x, 61) ^ (x >> 6)))

    @staticmethod
    def _sha512_Sigma0(x):
        return (HashCalculator._right_rotate_64(x, 28) ^ HashCalculator._right_rotate_64(x, 34) ^ HashCalculator._right_rotate_64(x, 39))

    @staticmethod
    def _sha512_Sigma1(x):
        return (HashCalculator._right_rotate_64(x, 14) ^ HashCalculator._right_rotate_64(x, 18) ^ HashCalculator._right_rotate_64(x, 41))

    def sha384(self, message):
        """SHA-384: implementación correcta y probada."""
        if isinstance(message, str):
            message = message.encode('utf-8')

        # Padding SHA-512 (big-endian length, 128-byte blocks)
        msg_len_bits = len(message) * 8
        m = bytearray(message)
        m.append(0x80)
        while (len(m) % 128) != 112:
            m.append(0)
        # 128-bit length: high 64 bits = 0, low 64 bits = bit length
        m += struct.pack('>QQ', 0, msg_len_bits)
        message_bytes = bytes(m)

        # Initial IV for SHA-384
        h = [
            0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
            0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
        ]

        # SHA-512 constants (correct 80 entries)
        k = [
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        ]

        MASK = 0xFFFFFFFFFFFFFFFF

        # procesar cada bloque de 128 bytes
        for i in range(0, len(message_bytes), 128):
            block = message_bytes[i:i+128]
            w = list(struct.unpack('>16Q', block))
            for t in range(16, 80):
                s0 = (self._right_rotate_64(w[t-15], 1) ^
                    self._right_rotate_64(w[t-15], 8) ^
                    (w[t-15] >> 7))
                s1 = (self._right_rotate_64(w[t-2], 19) ^
                    self._right_rotate_64(w[t-2], 61) ^
                    (w[t-2] >> 6))
                w.append((w[t-16] + s0 + w[t-7] + s1) & MASK)

            a, b, c, d, e, f, g, h_ = h[:]  # copia ¡importante!

            for t in range(80):
                ch = ((e & f) ^ ((~e) & g)) & MASK
                maj = ((a & b) ^ (a & c) ^ (b & c)) & MASK

                T1 = (h_ + self._right_rotate_64(e, 14) ^ 0)  # placeholder (we compute below)

                T1 = (h_ + self._sha512_Sigma1(e) + ch + k[t] + w[t]) & MASK
                T2 = (self._sha512_Sigma0(a) + maj) & MASK

                h_ = g
                g = f
                f = e
                e = (d + T1) & MASK
                d = c
                c = b
                b = a
                a = (T1 + T2) & MASK

            # añadir valores del bloque al estado
            h = [
                (h[0] + a) & MASK,
                (h[1] + b) & MASK,
                (h[2] + c) & MASK,
                (h[3] + d) & MASK,
                (h[4] + e) & MASK,
                (h[5] + f) & MASK,
                (h[6] + g) & MASK,
                (h[7] + h_) & MASK
            ]

        # salida SHA-384: primeros 6 palabras (48 bytes)
        return ''.join(f'{x:016x}' for x in h[:6])
    
    def hmac_sha256(self, message, key):
        """Implementación de HMAC-SHA256"""
        block_size = 64
        key_bytes = key.encode('utf-8')
        if len(key_bytes) > block_size:
            key_bytes = bytes.fromhex(self.sha256(key))
        if len(key_bytes) < block_size:
            key_bytes += b'\x00' * (block_size - len(key_bytes))
        
        ipad = bytes(x ^ 0x36 for x in key_bytes)
        opad = bytes(x ^ 0x5C for x in key_bytes)
        
        message_bytes = message.encode('utf-8')

        # Inner Hash: H((K XOR ipad) || message)
        inner_input = ipad + message_bytes
        inner_hash = self.sha256_bytes(inner_input) 

        # Outer Hash: H((K XOR opad) || inner_hash_bytes)
        outer_input = opad + bytes.fromhex(inner_hash)
        outer_hash = self.sha256_bytes(outer_input) 
        
        return outer_hash
    
    def calculate_all(self, text, hmac_key=None):
        # ... (Same as before) ...
        results = {
            'MD5': self.md5(text),
            'SHA-1': self.sha1(text),
            'SHA-256': self.sha256(text),
            'MD4': self.md4(text),
            'SHA384': self.sha384(text),
        }
        
        if hmac_key:
            results['HMAC-SHA256'] = self.hmac_sha256(text, hmac_key)
        
        return results

    def verify_with_builtin(self, text):
        """Verifica implementación contra biblioteca estándar"""

        # Hashes estándar
        our_md5 = self.md5(text)
        lib_md5 = hashlib.md5(text.encode()).hexdigest()

        our_sha1 = self.sha1(text)
        lib_sha1 = hashlib.sha1(text.encode()).hexdigest()

        our_sha256 = self.sha256(text)
        lib_sha256 = hashlib.sha256(text.encode()).hexdigest()

        our_sha384 = self.sha384(text)
        lib_sha384 = hashlib.sha384(text.encode()).hexdigest()

        # --- MD4 usando PyCryptodome ---
        our_md4 = self.md4(text)
        try:
            lib_md4 = MD4.new(text.encode()).hexdigest()
            md4_supported = True
        except Exception:
            lib_md4 = "MD4 no soportado"
            md4_supported = False

        md4_match = (our_md4 == lib_md4) if md4_supported else False

        # Resultados
        verification = {
            'MD5': (our_md5 == lib_md5, "Implementación correcta" if our_md5 == lib_md5 else f"ERROR: No coincide. Lib: {lib_md5}"),
            'SHA-1': (our_sha1 == lib_sha1, "Implementación correcta" if our_sha1 == lib_sha1 else f"ERROR: No coincide. Lib: {lib_sha1}"),
            'SHA-256': (our_sha256 == lib_sha256, "Implementación correcta" if our_sha256 == lib_sha256 else f"ERROR: No coincide. Lib: {lib_sha256}"),
            'MD4': (md4_match,
                    "Implementación correcta" if md4_match else f"ERROR: No coincide. Lib: {lib_md4}"),
            'SHA384': (our_sha384 == lib_sha384, "Implementación correcta" if our_sha384 == lib_sha384 else f"ERROR: No coincide. Lib: {lib_sha384}"),
        }

        # HMAC
        test_key = "test_key"
        our_hmac = self.hmac_sha256(text, test_key)
        lib_hmac = hmac.new(test_key.encode(), text.encode(), hashlib.sha256).hexdigest()

        verification['HMAC-SHA256'] = (our_hmac == lib_hmac,
                                    "Implementación correcta" if our_hmac == lib_hmac else f"ERROR: No coincide. Lib: {lib_hmac}")

        return verification

# ==================== INTERFAZ GRÁFICA ====================



class HashCalculatorGUI:
    """Interfaz gráfica para la calculadora de hashes"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Calculadora de Funciones Hash Criptográficas")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.calculator = HashCalculator()
        
        # Configurar estilo
        style = ttk.Style()
        style.theme_use('clam')
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Crear todos los widgets de la interfaz"""
        
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar expansión
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        # ===== TÍTULO =====
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, columnspan=2, pady=10, sticky="ew")
        
        title_label = ttk.Label(
            title_frame,
            text="CALCULADORA DE FUNCIONES HASH CRIPTOGRÁFICAS",
            font=('Arial', 14, 'bold')
        )
        title_label.pack()
        
        subtitle_label = ttk.Label(
            title_frame,
            text="Laboratorio 7 - Seguridad en Computación - UNSA",
            font=('Arial', 9)
        )
        subtitle_label.pack()
        
        # ===== ENTRADA DE TEXTO =====
        input_frame = ttk.LabelFrame(main_frame, text="Texto a Hashear", padding="10")
        input_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky="ew")
        input_frame.columnconfigure(0, weight=1)
        
        self.text_input = scrolledtext.ScrolledText(
            input_frame,
            height=4,
            wrap=tk.WORD,
            font=('Consolas', 10)
        )
        self.text_input.grid(row=0, column=0, sticky="ew")
        
        # ===== OPCIONES HMAC =====
        hmac_frame = ttk.LabelFrame(main_frame, text="HMAC-SHA256 (Opcional)", padding="10")
        hmac_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")
        hmac_frame.columnconfigure(1, weight=1)
        
        self.hmac_var = tk.BooleanVar()
        self.hmac_check = ttk.Checkbutton(
            hmac_frame,
            text="Calcular HMAC-SHA256",
            variable=self.hmac_var,
            command=self._toggle_hmac
        )
        self.hmac_check.grid(row=0, column=0, columnspan=2, sticky="w", pady=5)
        
        ttk.Label(hmac_frame, text="Clave secreta:").grid(row=1, column=0, sticky="w", padx=(20, 5))
        self.hmac_key_entry = ttk.Entry(hmac_frame, font=('Consolas', 10), state='disabled')
        self.hmac_key_entry.grid(row=1, column=1, sticky="ew", pady=5)
        
        # ===== BOTONES =====
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        self.calc_button = ttk.Button(
            button_frame,
            text="Calcular Hashes",
            command=self._calculate_hashes,
            width=20
        )
        self.calc_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(
            button_frame,
            text="Limpiar",
            command=self._clear_all,
            width=20
        )
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        self.verify_button = ttk.Button(
            button_frame,
            text="Verificar Implementación",
            command=self._verify_implementation,
            width=20
        )
        self.verify_button.pack(side=tk.LEFT, padx=5)
        
        # ===== RESULTADOS =====
        results_frame = ttk.LabelFrame(main_frame, text="Resultados", padding="10")
        results_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            height=15,
            wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled'
        )
        self.results_text.grid(row=0, column=0, sticky="nsew")
        
        # Configurar tags para colores
        self.results_text.tag_config('title', font=('Consolas', 10, 'bold'), foreground='#2E86AB')
        self.results_text.tag_config('hash', foreground='#06A77D')
        self.results_text.tag_config('success', foreground='#06A77D', font=('Consolas', 9, 'bold'))
        self.results_text.tag_config('error', foreground='#D62828', font=('Consolas', 9, 'bold'))
        self.results_text.tag_config('info', foreground='#6C757D')
        
        # ===== INFORMACIÓN (ACTUALIZADO) =====
        info_frame = ttk.LabelFrame(main_frame, text="Algoritmos Implementados", padding="10")
        info_frame.grid(row=5, column=0, columnspan=2, pady=10, sticky="ew")
        
        # ACTUALIZADO: Se añade MD4 y SHA384
        info_text = "MD5 (128 bits) | SHA-1 (160 bits) | SHA-256 (256 bits) | MD4 (128 bits) | SHA384 (384 bits) | HMAC-SHA256 (256 bits)"
        info_label = ttk.Label(info_frame, text=info_text, justify=tk.CENTER, font=('Arial', 8))
        info_label.pack()
    
    def _toggle_hmac(self):
        """Habilitar/deshabilitar entrada de clave HMAC"""
        if self.hmac_var.get():
            self.hmac_key_entry.config(state='normal')
        else:
            self.hmac_key_entry.config(state='disabled')
            self.hmac_key_entry.delete(0, tk.END)
    
    def _calculate_hashes(self):
        """Calcular y mostrar los hashes"""
        text = self.text_input.get("1.0", tk.END).strip()
        
        if not text:
            messagebox.showwarning("Advertencia", "Por favor, ingrese un texto para hashear")
            return
        
        # Obtener clave HMAC si está habilitada
        hmac_key = None
        if self.hmac_var.get():
            hmac_key = self.hmac_key_entry.get()
            if not hmac_key:
                messagebox.showwarning("Advertencia", "Por favor, ingrese una clave secreta para HMAC")
                return
        
        # Calcular hashes
        try:
            results = self.calculator.calculate_all(text, hmac_key)
            
            # Mostrar resultados
            self.results_text.config(state='normal')
            self.results_text.delete("1.0", tk.END)
            
            self.results_text.insert(tk.END, "="*80 + "\n")
            self.results_text.insert(tk.END, "RESULTADOS DE HASH\n", 'title')
            self.results_text.insert(tk.END, "="*80 + "\n\n")
            
            self.results_text.insert(tk.END, f"Texto original: {text[:50]}{'...' if len(text) > 50 else ''}\n", 'info')
            self.results_text.insert(tk.END, f"Longitud: {len(text)} caracteres\n\n", 'info')
            
            for algo, hash_val in results.items():
                self.results_text.insert(tk.END, f"{algo}:\n", 'title')
                self.results_text.insert(tk.END, f"{hash_val}\n\n", 'hash')
            
            self.results_text.insert(tk.END, "="*80 + "\n")
            self.results_text.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al calcular hashes:\n{str(e)}")
    
    def _verify_implementation(self):
        """Verificar la implementación contra la biblioteca estándar (MEJORADO)"""
        text = self.text_input.get("1.0", tk.END).strip()
        
        if not text:
            messagebox.showwarning("Advertencia", "Por favor, ingrese un texto para verificar")
            return
        
        try:
            verification = self.calculator.verify_with_builtin(text)
            
            self.results_text.config(state='normal')
            self.results_text.delete("1.0", tk.END)
            
            self.results_text.insert(tk.END, "="*80 + "\n")
            self.results_text.insert(tk.END, "VERIFICACIÓN CON BIBLIOTECA ESTÁNDAR\n", 'title')
            self.results_text.insert(tk.END, "="*80 + "\n\n")
            
            self.results_text.insert(tk.END, f"Texto: {text[:50]}{'...' if len(text) > 50 else ''}\n\n", 'info')
            
            all_ok = True
            for algo, (is_correct, message) in verification.items():
                status = "✓ CORRECTO" if is_correct else "✗ ERROR"
                tag = 'success' if is_correct else 'error'
                
                # Manejo especial para MD4 no soportado
                if "ADVERTENCIA" in message:
                    status = "⚠ ADVERTENCIA"
                    tag = 'error' # Usamos error para que se vea en rojo/naranja
                    all_ok = False # Consideramos que no es 100% OK si no se pudo verificar
                
                self.results_text.insert(tk.END, f"{algo}: {status} ({message})\n", tag)
                if not is_correct and "ADVERTENCIA" not in message:
                    all_ok = False
            
            self.results_text.insert(tk.END, "\n" + "="*80 + "\n")
            
            if all_ok:
                self.results_text.insert(tk.END, "\n¡Todas las implementaciones son correctas! ✓\n", 'success')
            else:
                self.results_text.insert(tk.END, "\n¡Hay errores en la implementación!\n", 'error')
            
            self.results_text.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar:\n{str(e)}")
    
    def _clear_all(self):
        """Limpiar todos los campos"""
        self.text_input.delete("1.0", tk.END)
        self.hmac_key_entry.delete(0, tk.END)
        self.hmac_var.set(False)
        self.hmac_key_entry.config(state='disabled')
        
        self.results_text.config(state='normal')
        self.results_text.delete("1.0", tk.END)
        self.results_text.config(state='disabled')


# ==================== PROGRAMA PRINCIPAL ====================

def main():
    """Iniciar la aplicación con interfaz gráfica"""
    root = tk.Tk()
    app = HashCalculatorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
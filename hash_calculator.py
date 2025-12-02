#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Calculadora de Funciones Hash Criptográficas
Laboratorio 7 - Seguridad en Computación
UNSA - Escuela Profesional de Ciencia de la Computación

Implementación  de MD5, SHA-1, SHA-256 y HMAC-SHA256
"""

import struct
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext


class HashCalculator:
    """
    Calculadora de funciones hash criptográficas
    Implementa MD5, SHA-1, SHA-256 y HMAC desde cero para fines educativos
    """
    
    def __init__(self):
        self.algorithms = ['MD5', 'SHA-1', 'SHA-256', 'HMAC-SHA256']
    
    # ==================== FUNCIONES AUXILIARES ====================
    
    @staticmethod
    def _left_rotate(n, b, bits=32):
        """Rotación circular a la izquierda"""
        n &= (2**bits - 1)
        return ((n << b) | (n >> (bits - b))) & (2**bits - 1)
    
    @staticmethod
    def _right_rotate(n, b, bits=32):
        """Rotación circular a la derecha"""
        n &= (2**bits - 1)
        return ((n >> b) | (n << (bits - b))) & (2**bits - 1)
    
    @staticmethod
    def _padding_md5_sha1(message_bytes):
        """Padding para MD5 y SHA-1 (formato Merkle-Damgård)"""
        msg_len = len(message_bytes)
        message_bytes += b'\x80'  # Agregar bit 1 seguido de ceros
        
        # Rellenar con ceros hasta que len mod 512 = 448
        while (len(message_bytes) * 8) % 512 != 448:
            message_bytes += b'\x00'
        
        # Agregar longitud original en bits (64 bits, little endian para MD5)
        message_bytes += struct.pack('<Q', msg_len * 8)
        return message_bytes
    
    @staticmethod
    def _padding_sha256(message_bytes):
        """Padding para SHA-256 (formato Merkle-Damgård, big endian)"""
        msg_len = len(message_bytes)
        message_bytes += b'\x80'
        
        while (len(message_bytes) * 8) % 512 != 448:
            message_bytes += b'\x00'
        
        # Agregar longitud en big endian
        message_bytes += struct.pack('>Q', msg_len * 8)
        return message_bytes
    
    # ==================== IMPLEMENTACIÓN MD5 ====================
    
    def md5(self, message):
        """
        Implementación de MD5
        - 128 bits de salida
        - Little endian
        - 64 vueltas (4 rondas de 16)
        - 4 vectores: A, B, C, D
        """
        # Constantes MD5: floor(2^32 * abs(sin(i+1)))
        import math
        T = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
        
        # Valores iniciales
        A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
        
        # Funciones auxiliares
        F = lambda x, y, z: (x & y) | (~x & z)
        G = lambda x, y, z: (x & z) | (y & ~z)
        H = lambda x, y, z: x ^ y ^ z
        I = lambda x, y, z: y ^ (x | ~z)
        
        # Padding
        message_bytes = self._padding_md5_sha1(message.encode('utf-8'))
        
        # Shifts para cada vuelta
        shifts = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + \
                 [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
        
        # Procesar bloques de 512 bits
        for offset in range(0, len(message_bytes), 64):
            block = message_bytes[offset:offset + 64]
            M = list(struct.unpack('<16I', block))
            
            # Guardar valores iniciales
            AA, BB, CC, DD = A, B, C, D
            
            # 64 vueltas
            for i in range(64):
                if i < 16:
                    f = F(B, C, D)
                    g = i
                elif i < 32:
                    f = G(B, C, D)
                    g = (5 * i + 1) % 16
                elif i < 48:
                    f = H(B, C, D)
                    g = (3 * i + 5) % 16
                else:
                    f = I(B, C, D)
                    g = (7 * i) % 16
                
                f = (f + A + T[i] + M[g]) & 0xFFFFFFFF
                A = D
                D = C
                C = B
                B = (B + self._left_rotate(f, shifts[i])) & 0xFFFFFFFF
            
            # Sumar valores
            A = (A + AA) & 0xFFFFFFFF
            B = (B + BB) & 0xFFFFFFFF
            C = (C + CC) & 0xFFFFFFFF
            D = (D + DD) & 0xFFFFFFFF
        
        # Resultado en little endian (formato de bytes)
        result = struct.pack('<4I', A, B, C, D)
        return result.hex()
    
    # ==================== IMPLEMENTACIÓN SHA-1 ====================
    
    def sha1(self, message):
        """
        Implementación de SHA-1
        - 160 bits de salida
        - Big endian
        - 80 vueltas (4 rondas de 20)
        - 5 vectores: A, B, C, D, E
        """
        # Valores iniciales
        h0, h1, h2, h3, h4 = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 
                               0x10325476, 0xC3D2E1F0)
        
        # Constantes
        K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
        
        # Padding (big endian)
        message_bytes = message.encode('utf-8') + b'\x80'
        msg_len = len(message.encode('utf-8'))
        
        while (len(message_bytes) * 8) % 512 != 448:
            message_bytes += b'\x00'
        message_bytes += struct.pack('>Q', msg_len * 8)
        
        # Procesar bloques
        for offset in range(0, len(message_bytes), 64):
            block = message_bytes[offset:offset + 64]
            W = list(struct.unpack('>16I', block))
            
            # Expansión de mensaje: 16 -> 80 palabras
            for i in range(16, 80):
                W.append(self._left_rotate(
                    W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1))
            
            # Inicializar variables
            a, b, c, d, e = h0, h1, h2, h3, h4
            
            # 80 vueltas
            for i in range(80):
                if i < 20:
                    f = (b & c) | (~b & d)
                    k = K[0]
                elif i < 40:
                    f = b ^ c ^ d
                    k = K[1]
                elif i < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = K[2]
                else:
                    f = b ^ c ^ d
                    k = K[3]
                
                temp = (self._left_rotate(a, 5) + f + e + k + W[i]) & 0xFFFFFFFF
                e, d, c, b, a = d, c, self._left_rotate(b, 30), a, temp
            
            # Actualizar hash
            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF
        
        return ''.join(f'{x:08x}' for x in [h0, h1, h2, h3, h4])
    
    # ==================== IMPLEMENTACIÓN SHA-256 ====================
    
    def sha256(self, message):
        """
        Implementación de SHA-256
        - 256 bits de salida
        - Big endian
        - 64 vueltas
        - 8 vectores
        """
        # Valores iniciales (primeros 32 bits de las raíces cuadradas 
        # de los primeros 8 primos)
        h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        # Constantes (primeros 32 bits de las raíces cúbicas 
        # de los primeros 64 primos)
        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        
        # Padding
        message_bytes = self._padding_sha256(message.encode('utf-8'))
        
        # Procesar bloques de 512 bits
        for offset in range(0, len(message_bytes), 64):
            block = message_bytes[offset:offset + 64]
            w = list(struct.unpack('>16I', block))
            
            # Expansión: 16 -> 64 palabras
            for i in range(16, 64):
                s0 = (self._right_rotate(w[i-15], 7) ^ 
                      self._right_rotate(w[i-15], 18) ^ (w[i-15] >> 3))
                s1 = (self._right_rotate(w[i-2], 17) ^ 
                      self._right_rotate(w[i-2], 19) ^ (w[i-2] >> 10))
                w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)
            
            # Inicializar variables de trabajo
            a, b, c, d, e, f, g, h_var = h
            
            # 64 vueltas
            for i in range(64):
                S1 = (self._right_rotate(e, 6) ^ 
                      self._right_rotate(e, 11) ^ 
                      self._right_rotate(e, 25))
                ch = (e & f) ^ (~e & g)
                temp1 = (h_var + S1 + ch + k[i] + w[i]) & 0xFFFFFFFF
                
                S0 = (self._right_rotate(a, 2) ^ 
                      self._right_rotate(a, 13) ^ 
                      self._right_rotate(a, 22))
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & 0xFFFFFFFF
                
                h_var, g, f, e = g, f, e, (d + temp1) & 0xFFFFFFFF
                d, c, b, a = c, b, a, (temp1 + temp2) & 0xFFFFFFFF
            
            # Actualizar hash
            h = [(x + y) & 0xFFFFFFFF for x, y in 
                 zip(h, [a, b, c, d, e, f, g, h_var])]
        
        return ''.join(f'{x:08x}' for x in h)
    
    # ==================== IMPLEMENTACIÓN HMAC ====================
    
    def hmac_sha256(self, message, key):
        """
        Implementación de HMAC usando SHA-256
        HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
        donde:
        - K': clave ajustada al tamaño del bloque
        - ipad: 0x36 repetido
        - opad: 0x5c repetido
        """
        block_size = 64  # SHA-256 usa bloques de 512 bits = 64 bytes
        
        key_bytes = key.encode('utf-8')
        
        # Ajustar clave al tamaño del bloque
        if len(key_bytes) > block_size:
            key_bytes = bytes.fromhex(self.sha256(key))
        if len(key_bytes) < block_size:
            key_bytes += b'\x00' * (block_size - len(key_bytes))
        
        # Calcular pads
        ipad = bytes(x ^ 0x36 for x in key_bytes)
        opad = bytes(x ^ 0x5C for x in key_bytes)
        
        # HMAC = H(opad || H(ipad || message))
        inner_hash = self.sha256((ipad + message.encode('utf-8')).decode('latin-1'))
        outer_hash = self.sha256((opad + bytes.fromhex(inner_hash)).decode('latin-1'))
        
        return outer_hash
    
    # ==================== INTERFAZ DE CALCULADORA ====================
    
    def calculate_all(self, text, hmac_key=None):
        """Calcula todos los hashes para un texto dado"""
        results = {
            'MD5': self.md5(text),
            'SHA-1': self.sha1(text),
            'SHA-256': self.sha256(text),
        }
        
        if hmac_key:
            results['HMAC-SHA256'] = self.hmac_sha256(text, hmac_key)
        
        return results
    
    def verify_with_builtin(self, text):
        """Verifica implementación contra biblioteca estándar"""
        our_md5 = self.md5(text)
        lib_md5 = hashlib.md5(text.encode()).hexdigest()
        
        our_sha1 = self.sha1(text)
        lib_sha1 = hashlib.sha1(text.encode()).hexdigest()
        
        our_sha256 = self.sha256(text)
        lib_sha256 = hashlib.sha256(text.encode()).hexdigest()
        
        return {
            'MD5': our_md5 == lib_md5,
            'SHA-1': our_sha1 == lib_sha1,
            'SHA-256': our_sha256 == lib_sha256,
        }


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
        
        # ===== INFORMACIÓN =====
        info_frame = ttk.LabelFrame(main_frame, text="Algoritmos Implementados", padding="10")
        info_frame.grid(row=5, column=0, columnspan=2, pady=10, sticky="ew")
        
        info_text = "MD5 (128 bits) | SHA-1 (160 bits) | SHA-256 (256 bits) | HMAC-SHA256 (256 bits)"
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
        """Verificar la implementación contra la biblioteca estándar"""
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
            for algo, is_correct in verification.items():
                status = "✓ CORRECTO" if is_correct else "✗ ERROR"
                tag = 'success' if is_correct else 'error'
                self.results_text.insert(tk.END, f"{algo}: {status}\n", tag)
                if not is_correct:
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
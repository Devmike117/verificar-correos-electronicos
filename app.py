
import tkinter as tk
from tkinter import ttk, messagebox
import re
import dns.resolver
import smtplib
import socket
import webbrowser
import os, sys

# =========================================================
# Función para cargar recursos (icono, imágenes.)
# =========================================================

def resource_path(relative_path):

    try:
        base_path = sys._MEIPASS  
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# =========================================================
# dominios oficiales conocidos (para phishing)
# =========================================================

DOMINIOS_OFICIALES = [
    "google.com", "gmail.com", "outlook.com", "hotmail.com",
    "yahoo.com", "apple.com", "icloud.com", "microsoft.com",
    "facebook.com", "twitter.com", "linkedin.com",
    "steampowered.com", "amazon.com", "amazon.com.mx"
]

def dominio_oficial(dominio):
    return dominio.lower() in DOMINIOS_OFICIALES

# =========================================================
# validación de correo 
# =========================================================

def validar_correo(P):
    if P == "":
        return True
    regex = r'^[\w\.-]*@?[\w\.-]*\.?[\w]{0,4}$'
    return re.match(regex, P) is not None

def verificar_sintaxis(correo):
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(regex, correo))

def obtener_mx(dominio):
    try:
        respuestas = dns.resolver.resolve(dominio, 'MX')
        mx_records = sorted([(r.preference, r.exchange.to_text()) for r in respuestas], key=lambda x: x[0])
        return [record[1] for record in mx_records]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return None

def verificar_smtp(mx_hosts, correo):
    if not mx_hosts:
        return False, "No hay servidores MX para verificar SMTP"
    for host in mx_hosts:
        try:
            server = smtplib.SMTP(host, timeout=8)
            server.starttls()
            server.ehlo_or_helo_if_needed()
            server.mail('auditor@localtest.com')
            code, message = server.rcpt(correo)
            server.quit()
            if code in [250, 251]:
                return True, f"Servidor {host} confirmó que el buzón existe ✔"
            else:
                return False, f"Servidor {host} respondió: {code} {message.decode(errors='ignore')}"
        except (smtplib.SMTPException, socket.error):
            continue
    return False, "No fue posible verificar el buzón en ningún servidor MX"

def verificar_dnsbl(dominio):
    dnsbl_servers = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]
    resultados = {}
    if not dominio:
        return {bl: "Dominio no válido" for bl in dnsbl_servers}
    try:
        ips = dns.resolver.resolve(dominio, 'A')
        for ip in ips:
            ip_reverse = ".".join(reversed(str(ip).split(".")))
            for bl in dnsbl_servers:
                try:
                    dns.resolver.resolve(f"{ip_reverse}.{bl}", 'A')
                    resultados[bl] = "Listado en blacklist ✖"
                except dns.resolver.NXDOMAIN:
                    resultados[bl] = "No listado ✔"
                except dns.exception.DNSException:
                    resultados[bl] = "Error DNS"
    except dns.resolver.NXDOMAIN:
        resultados = {bl: "Dominio no existe" for bl in dnsbl_servers}
    except dns.exception.DNSException:
        resultados = {bl: "Error DNS" for bl in dnsbl_servers}
    return resultados

def verificar_autenticacion(dominio):
    registros = {}
    if not dominio:
        return registros
    try:
        txts = dns.resolver.resolve(dominio, 'TXT')
        for txt in txts:
            t = txt.to_text().strip('"')
            if t.startswith("v=spf1"):
                registros["SPF"] = t
            elif t.startswith("v=DMARC1"):
                registros["DMARC"] = t
            elif "dkim" in t.lower():
                registros["DKIM"] = t
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException:
        pass
    return registros

# =========================================================
# Similitud de dominios para detectar phishing
# =========================================================

def levenshtein(a, b):
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev_row = range(len(b) + 1)
    for i, c1 in enumerate(a):
        curr_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]

def detectar_diferencia(dominio, oficial):
    diferencias = []
    min_len = min(len(dominio), len(oficial))
    for i in range(min_len):
        if dominio[i] != oficial[i]:
            diferencias.append(f"Posición {i+1}: '{dominio[i]}' en correo vs '{oficial[i]}' esperado")

    if len(dominio) > len(oficial):
        diferencias.append(f"Extra en dominio: '{dominio[min_len:]}'")
    elif len(oficial) > len(dominio):
        diferencias.append(f"Falta en dominio: debería tener '{oficial[min_len:]}'")
    return diferencias

def detectar_errores(dominio):
    for oficial in DOMINIOS_OFICIALES:
        distancia = levenshtein(dominio, oficial)
        if 0 < distancia <= 2:
            diferencias = detectar_diferencia(dominio, oficial)
            detalle = "\n".join(diferencias) if diferencias else "Diferencias menores detectadas."
            return f"⚠︎ El dominio '{dominio}' es muy similar a '{oficial}' (distancia {distancia}).\nDetalles: {detalle}"
    return None


# =========================================================
# Auditoría principal
# =========================================================

def auditar():
    correo = correo_entry.get().strip()
    if not correo:
        messagebox.showwarning("Atención", "Ingrese un correo para auditar")
        return

    if not verificar_sintaxis(correo):
        messagebox.showerror("Correo inválido", "El correo ingresado no tiene una estructura válida.\nFormato esperado: ejemplo@dominio.com")
        return

    for widget in reporte_frame.winfo_children():
        widget.destroy()

    riesgo_total = 0
    max_riesgo = 7

    tk.Label(reporte_frame, text=f"Resultado de: {correo}",
             font=("Helvetica Neue", 18, "bold"),
             fg="#1d1d1f", bg="#f5f5f7").pack(pady=(10, 20))

    # =======================
    # 1. Sintaxis
    # =======================
    
    sintaxis_ok = verificar_sintaxis(correo)
    frame_sintaxis = tk.Frame(reporte_frame, bg="#ffffff", bd=1, relief="solid")
    frame_sintaxis.pack(fill="x", padx=20, pady=5)
    tk.Label(frame_sintaxis, text="🔹 Sintaxis", font=("Helvetica Neue", 14, "bold"), bg="#ffffff").pack(anchor="w", padx=10, pady=5)
    tk.Label(frame_sintaxis,
             text="Correcta ✔ " if sintaxis_ok else "Incorrecta ✖",
             font=("Helvetica Neue", 12),
             bg="#ffffff", fg="#0a84ff" if sintaxis_ok else "#ff3b30").pack(anchor="w", padx=20, pady=(0, 10))
    if not sintaxis_ok:
        riesgo_total += 2

    # =======================
    # 2. Dominio y MX
    # =======================
    
    dominio = correo.split('@')[1] if '@' in correo else ""
    mx_hosts = obtener_mx(dominio)
    frame_mx = tk.Frame(reporte_frame, bg="#ffffff", bd=1, relief="solid")
    frame_mx.pack(fill="x", padx=20, pady=5)
    tk.Label(frame_mx, text="🔹 Dominio y MX", font=("Helvetica Neue", 14, "bold"), bg="#ffffff").pack(anchor="w", padx=10, pady=5)
    tk.Label(frame_mx, text=f"Dominio detectado: {dominio if dominio else 'No válido'}",
             font=("Helvetica Neue", 12), bg="#ffffff").pack(anchor="w", padx=20)

    error_msg = detectar_errores(dominio)
    if error_msg:
        tk.Label(frame_mx, text=error_msg, font=("Helvetica Neue", 12),
                 bg="#ffffff", fg="#ff9500", wraplength=700, justify="left").pack(anchor="w", padx=20, pady=(5, 10))
        riesgo_total += 1

    if not mx_hosts:
        tk.Label(frame_mx, text="✖ El dominio no tiene servidores MX válidos (correo no entregable)",
                 font=("Helvetica Neue", 12), bg="#ffffff", fg="#ff3b30").pack(anchor="w", padx=20, pady=(5, 10))
        riesgo_total += 2

    # =======================
    # 3. SMTP
    # =======================
    
    if mx_hosts:
        frame_smtp = tk.Frame(reporte_frame, bg="#ffffff", bd=1, relief="solid")
        frame_smtp.pack(fill="x", padx=20, pady=5)
        tk.Label(frame_smtp, text="🔹 Conexión SMTP", font=("Helvetica Neue", 14, "bold"), bg="#ffffff").pack(anchor="w", padx=10, pady=5)
        exito, mensaje = verificar_smtp(mx_hosts, correo)
        color = "#0a84ff" if exito else "#ff3b30"
        if not exito:
            riesgo_total += 1
        tk.Label(frame_smtp, text=mensaje, font=("Helvetica Neue", 12), bg="#ffffff", fg=color, wraplength=700, justify="left").pack(anchor="w", padx=20, pady=(0, 10))

    # =======================
    # 4. DNSBL
    # =======================
    
    frame_dnsbl = tk.Frame(reporte_frame, bg="#ffffff", bd=1, relief="solid")
    frame_dnsbl.pack(fill="x", padx=20, pady=5)
    tk.Label(frame_dnsbl, text="Listas negras (DNSBL)", font=("Helvetica Neue", 14, "bold"), bg="#ffffff").pack(anchor="w", padx=10, pady=5)

    dnsbl_resultados = verificar_dnsbl(dominio)

    for bl, res in dnsbl_resultados.items():
        if "EN LISTA NEGRA" in res:
            color = "#ff3b30"  
            riesgo_total += 2
        elif "No listado" in res:
            color = "#0a84ff"  
        else: 
            res = "No se pudo verificar (posible bloqueo o restricción del servicio)"
            color = "#ff9500" 
        
        tk.Label(frame_dnsbl, text=f"{bl}: {res}", font=("Helvetica Neue", 12),
                bg="#ffffff", fg=color, wraplength=700, justify="left").pack(anchor="w", padx=20, pady=2)

    # =======================
    # 5. SPF/DKIM/DMARC
    # =======================
    
    frame_auth = tk.Frame(reporte_frame, bg="#ffffff", bd=1, relief="solid")
    frame_auth.pack(fill="x", padx=20, pady=5)
    tk.Label(frame_auth, text="🔹 Autenticación SPF/DKIM/DMARC", font=("Helvetica Neue", 14, "bold"), bg="#ffffff").pack(anchor="w", padx=10, pady=5)
    auth = verificar_autenticacion(dominio)
    if auth:
        for k, v in auth.items():
            tk.Label(frame_auth, text=f"{k}: {v}", font=("Helvetica Neue", 12),
                     bg="#ffffff", fg="#0a84ff", wraplength=700, justify="left").pack(anchor="w", padx=20)
    else:
        tk.Label(frame_auth, text="No se encontraron registros SPF, DKIM o DMARC",
                 font=("Helvetica Neue", 12), bg="#ffffff", fg="#ff9500",
                 wraplength=700, justify="left").pack(anchor="w", padx=20)
        riesgo_total += 1

    # =======================
    # Resultado final
    # =======================
    
    confianza = max(0, 100 - int((riesgo_total / max_riesgo) * 100))

    if confianza >= 80:
        estado = "✔ Seguro"
        color_final = "#0a84ff"  
    elif confianza >= 60:
        estado = "⚠︎ Peligro, evitar enviar info "
        color_final = "#ff9500"  
    elif confianza >= 50:
        estado = "✖ Sospechoso / Posible Phishing"
        color_final = "#ff3b30"  
    else:
        estado = "! ⚠︎ Muy Riesgoso / Phishing"
        color_final = "#8b0000" 

    frame_final = tk.Frame(reporte_frame, bg="#e5f0ff", bd=2, relief="solid")
    frame_final.pack(fill="x", padx=20, pady=15)
    tk.Label(frame_final, text=f"{estado}",
             font=("Helvetica Neue", 16, "bold"),
             bg="#e5f0ff", fg=color_final).pack(padx=10, pady=10)

# =========================================================
# Interfaz principal
# =========================================================

root = tk.Tk()
root.title("Auditoría de Correos Electrónicos")
root.geometry("800x750")
root.configure(bg="#f5f5f7")

# =========================================================
# Icono
# =========================================================

root.iconbitmap(resource_path("icono_app.ico"))

# Entrada
tk.Label(root, text="Ingrese el correo a auditar:", font=("Helvetica Neue", 14), bg="#f5f5f7").pack(pady=(20,5))
vcmd = (root.register(validar_correo), '%P')
correo_entry = ttk.Entry(root, width=50, font=("Helvetica Neue", 12), validate="key", validatecommand=vcmd)
correo_entry.pack(pady=(0,10))

# Botón
auditar_btn = tk.Button(root, text="Verificar", command=auditar,
                        bg="#0a84ff", fg="white", font=("Helvetica Neue", 12, "bold"),
                        activebackground="#7f8183", activeforeground="white", bd=0)
auditar_btn.pack(pady=10)

# =========================================================
# Área de reporte 
# =========================================================

canvas = tk.Canvas(root, bg="#f5f5f7", highlightthickness=0)
style = ttk.Style()
style.theme_use('clam')
style.configure("Vertical.TScrollbar",
                troughcolor="#f5f5f7", background="#0a84ff",
                arrowcolor="#0a84ff", bordercolor="#f5f5f7",
                lightcolor="#0a84ff", darkcolor="#0a84ff")

scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview, style="Vertical.TScrollbar")
reporte_frame = tk.Frame(canvas, bg="#f5f5f7")
reporte_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
canvas.create_window((0, 0), window=reporte_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)
canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")


root.mainloop()

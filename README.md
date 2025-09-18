# verificar-correos-electronicos

Este proyecto es una herramienta de escritorio desarrollada en Python que permite auditar direcciones de correo electrónico en tiempo real. Evalúa la validez sintáctica, existencia del dominio, configuración de servidores MX, autenticación SPF/DKIM/DMARC y presencia en listas negras (DNSBL). También detecta posibles intentos de phishing mediante análisis de similitud de dominios.

<table>
  <tr>
    <td align="center">
      <strong>Correo electrónico real</strong><br>
      <img src="https://raw.githubusercontent.com/Devmike117/verificar-correos-electronicos/refs/heads/main/preview/real.png" width="450"/>
    </td>
    <td align="center">
      <strong>Correo electrónico falso (phishing)</strong><br>
      <img src="https://raw.githubusercontent.com/Devmike117/verificar-correos-electronicos/refs/heads/main/preview/phishing.png" width="450"/>
    </td>
  </tr>
</table>

---
## Características

- Validación de sintaxis de correos electrónicos

- Verificación de servidores MX mediante DNS

- Comprobación de existencia del buzón vía conexión SMTP

- Detección de dominios en listas negras (Spamhaus, Spamcop, Barracuda)

- Análisis de autenticación SPF, DKIM y DMARC

- Detección de phishing por similitud de dominios


---
## Requisitos
- Python 3.11+

Librerías:

- `tkinter`

- `re`

- `dns.resolver`

- `smtplib`

- `socket`

---
## Instala dependencias con:

```bash
pip install -r requirements.txt
```


## Clonación del repositorio

1. Clona este repositorio o descarga los archivos:
```bash
git clone https://github.com/Devmike117/verificar-correos-electronicos.git
```

---

## Utilizar el programa en .exe

Si no deseas instalar Python ni ejecutar el código manualmente, puedes usar el archivo ejecutable `.exe` que viene empaquetado.

### Pasos para usarlo:
1. Descarga el archivo `verificar-correo.exe` desde la sección de [Releases](https://github.com/Devmike117/verificar-correos-electronicos/releases).
2. Haz doble clic para abrir la aplicación.
3. Si aparece una advertencia de SmartScreen, haz clic en **“Más información”** y luego en **“Ejecutar de todas formas”**.
4. Se ejecutará el programa y podrás verificar si el correo es real o se trata de una estafa o phishing.
---
### Recomendaciones:
- Ejecuta el `.exe` en Windows 10 o superior.
- Si tu antivirus bloquea el archivo, verifica que proviene de este repositorio oficial.

---
### Seguridad
Este proyecto no almacena correos ni realiza envíos. Todas las verificaciones se hacen de forma local y segura.

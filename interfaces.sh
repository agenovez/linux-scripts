#!/bin/bash

# ============================================================
# Proxmox VE - Estado de interfaces Ethernet físicas
# Solo lectura - NO modifica configuración
# ============================================================

printf "\n"
echo "================================================================================================================"
echo "                         PROXMOX - INTERFACES DE RED FISICAS"
echo "================================================================================================================"

printf "%-18s %-10s %-15s %-10s %-10s %-18s %-15s %-12s\n" \
       "INTERFAZ" "ADMIN" "ENLACE" "VELOCIDAD" "DUPLEX" "MAC" "DRIVER" "MASTER"

echo "----------------------------------------------------------------------------------------------------------------"

for path in /sys/class/net/*; do

    iface=$(basename "$path")

    # Excluir loopback
    [ "$iface" = "lo" ] && continue

    # Excluir dispositivos virtuales:
    # vmbr, tap, veth, fwbr, fwpr, bond virtual, VLAN, etc.
    realpath=$(readlink -f "$path")

    if [[ "$realpath" == *"/virtual/"* ]]; then
        continue
    fi

    # Debe tener dispositivo físico asociado
    [ ! -e "$path/device" ] && continue

    # --------------------------------------------------------
    # Estado administrativo
    # --------------------------------------------------------

    flags=$(ip -o link show dev "$iface" 2>/dev/null \
        | sed -n 's/^[0-9]\+: [^:]*: <\([^>]*\)>.*/\1/p')

    if [[ ",$flags," == *,UP,* ]]; then
        admin="UP"
    else
        admin="DOWN"
    fi

    # --------------------------------------------------------
    # Carrier físico
    # --------------------------------------------------------

    if [ -f "$path/carrier" ]; then
        carrier=$(cat "$path/carrier" 2>/dev/null)

        if [ "$carrier" = "1" ]; then
            link="CONECTADA"
        else
            if [ "$admin" = "DOWN" ]; then
                link="ADMIN-DOWN"
            else
                link="SIN-CABLE"
            fi
        fi
    else
        link="DESCONOCIDO"
    fi

    # --------------------------------------------------------
    # Velocidad
    # --------------------------------------------------------

    if [ -f "$path/speed" ]; then
        speed=$(cat "$path/speed" 2>/dev/null)

        if [[ "$speed" =~ ^[0-9]+$ ]] && [ "$speed" -gt 0 ]; then
            speed="${speed}M"
        else
            speed="-"
        fi
    else
        speed="-"
    fi

    # --------------------------------------------------------
    # Duplex
    # --------------------------------------------------------

    if [ -f "$path/duplex" ]; then
        duplex=$(cat "$path/duplex" 2>/dev/null)
    else
        duplex="-"
    fi

    # --------------------------------------------------------
    # MAC
    # --------------------------------------------------------

    mac=$(cat "$path/address" 2>/dev/null)
    [ -z "$mac" ] && mac="-"

    # --------------------------------------------------------
    # Driver
    # --------------------------------------------------------

    if [ -L "$path/device/driver" ]; then
        driver=$(basename "$(readlink -f "$path/device/driver")")
    else
        driver="-"
    fi

    # --------------------------------------------------------
    # Bridge / Bond al que pertenece
    # --------------------------------------------------------

    if [ -L "$path/master" ]; then
        master=$(basename "$(readlink -f "$path/master")")
    else
        master="-"
    fi

    printf "%-18s %-10s %-15s %-10s %-10s %-18s %-15s %-12s\n" \
           "$iface" "$admin" "$link" "$speed" "$duplex" "$mac" "$driver" "$master"

done

echo "================================================================================================================"
echo
echo "Leyenda:"
echo "  CONECTADA   = Existe señal física / carrier"
echo "  SIN-CABLE   = Interfaz habilitada pero sin enlace físico"
echo "  ADMIN-DOWN  = Interfaz deshabilitada administrativamente"
echo

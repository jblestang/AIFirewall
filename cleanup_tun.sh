#!/bin/bash
# Script to remove TUN interfaces
# Usage: sudo ./cleanup_tun.sh

echo "Removing TUN interfaces..."

# macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Detected macOS"
    
    # Get list of all utun interfaces
    INTERFACES=$(ifconfig | grep -E "^utun" | awk '{print $1}' | sed 's/://')
    
    if [ -z "$INTERFACES" ]; then
        echo "No utun interfaces found."
    else
        for iface in $INTERFACES; do
            echo "Removing $iface..."
            # First bring it down
            sudo ifconfig "$iface" down 2>/dev/null
            # Then destroy it (if supported)
            sudo ifconfig "$iface" destroy 2>/dev/null || true
        done
        echo "Done. Remaining interfaces:"
        ifconfig | grep -E "^utun" || echo "  (none)"
    fi

# Linux
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Detected Linux"
    
    # Get list of all tap interfaces
    INTERFACES=$(ip tuntap show | grep tap | awk '{print $1}' | sed 's/://')
    
    if [ -z "$INTERFACES" ]; then
        echo "No tap interfaces found."
    else
        for iface in $INTERFACES; do
            echo "Removing $iface..."
            sudo ip tuntap del mode tap name "$iface" 2>/dev/null || \
            sudo ip link delete "$iface" 2>/dev/null || true
        done
        echo "Done. Remaining interfaces:"
        ip tuntap show | grep tap || echo "  (none)"
    fi
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi


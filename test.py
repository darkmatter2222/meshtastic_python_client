import argparse
import os
import time
import sys
import meshtastic
import meshtastic.serial_interface
import serial.tools.list_ports
import pprint


# Auto-detect the Meshtastic device port
def find_meshtastic_port(preferred_port=None):
    # 1) explicit override
    if preferred_port:
        return preferred_port

    # 2) environment override
    env_port = os.environ.get("MESHTASTIC_PORT")
    if env_port:
        return env_port

    # 3) auto-detect from available serial ports
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        raise RuntimeError("No serial ports found. Connect your Meshtastic device and try again.")

    # Try to find a USB/Serial device by common keywords in description/hwid/manufacturer
    keywords = ("USB", "UART", "CP210", "CH340", "FTDI", "Silicon", "USB Serial")
    for p in ports:
        desc = (p.description or "").lower()
        hwid = (p.hwid or "").lower()
        if any(k.lower() in desc or k.lower() in hwid for k in keywords):
            return p.device

    # Fallback: if there's exactly one port, use it
    if len(ports) == 1:
        return ports[0].device

    # Otherwise fail with a helpful message listing candidates
    candidates = ", ".join(p.device for p in ports)
    raise RuntimeError(f"Multiple serial ports found ({candidates}). Please set MESHTASTIC_PORT or pass --port to select one.")


def find_channel_index(iface, channel_name):
    """Try to find a channel index on the device by name.

    Returns integer index or None if not found.
    """
    if not channel_name:
        return None

    # helper to get name and numeric index from a channel object
    def _extract_name_and_index(ch):
        if ch is None:
            return None, None
        # dict-style
        if isinstance(ch, dict):
            name = ch.get("name") or ch.get("label") or ch.get("channelName")
            idx = ch.get("index")
            return name, idx
        # protobuf-like object: look for settings.name and an index attribute
        settings = getattr(ch, "settings", None)
        name = None
        if settings is not None:
            if isinstance(settings, dict):
                name = settings.get("name") or settings.get("label")
            else:
                name = getattr(settings, "name", None) or getattr(settings, "label", None)
        name = name or getattr(ch, "name", None) or getattr(ch, "label", None)
        idx = getattr(ch, "index", None)
        return name, idx

    # 1) check iface._localChannels or iface.localChannels (protobuf/list)
    local = getattr(iface, "_localChannels", None) or getattr(iface, "localChannels", None)
    if local:
        try:
            for ch in list(local):
                name, idx = _extract_name_and_index(ch)
                if name and name.lower() == channel_name.lower():
                    # prefer numeric index if available
                    return idx if idx is not None else None
        except Exception:
            pass

    # 2) try radioConfig dict
    rc = getattr(iface, "radioConfig", None)
    if isinstance(rc, dict):
        prim = rc.get("channels") or rc.get("channel") or rc.get("channelList") or []
        sec = rc.get("secondaryChannels") or rc.get("secondary") or []
        for ch in list(prim) + list(sec):
            name, idx = _extract_name_and_index(ch)
            if name and name.lower() == channel_name.lower():
                return idx

    # 3) try getConfig() if available
    try:
        cfg = iface.getConfig()
        if isinstance(cfg, dict):
            prim = cfg.get("channels") or cfg.get("channel") or []
            sec = cfg.get("secondaryChannels") or cfg.get("secondary") or []
            for ch in list(prim) + list(sec):
                name, idx = _extract_name_and_index(ch)
                if name and name.lower() == channel_name.lower():
                    return idx
    except Exception:
        pass

    return None


def get_device_channels(iface, timeout=5.0, poll_interval=0.5):
    """Return a list of channel dicts (may be empty). Retry for `timeout` seconds while waiting for device to respond."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        # 1) try _localChannels first
        local = getattr(iface, "_localChannels", None) or getattr(iface, "localChannels", None)
        if local:
            try:
                out = []
                for ch in list(local):
                    out.append(("local", ch))
                return out
            except Exception:
                pass

        # 2) Try cached radioConfig
        rc = getattr(iface, "radioConfig", None)
        if isinstance(rc, dict):
            # collect primary + secondary if present
            prim = rc.get("channels") or rc.get("channel") or rc.get("channelList") or []
            sec = rc.get("secondaryChannels") or rc.get("secondary_channel_list") or rc.get("secondary") or []
            # Normalize to list
            prim = list(prim) if prim else []
            sec = list(sec) if sec else []
            if prim or sec:
                # return combined list with origin markers
                out = []
                for ch in prim:
                    out.append(("primary", ch))
                for ch in sec:
                    out.append(("secondary", ch))
                return out

        # Try getConfig() call
        try:
            cfg = iface.getConfig()
            if isinstance(cfg, dict):
                prim = cfg.get("channels") or cfg.get("channel") or []
                sec = cfg.get("secondaryChannels") or cfg.get("secondary_channel_list") or cfg.get("secondary") or []
                prim = list(prim) if prim else []
                sec = list(sec) if sec else []
                if prim or sec:
                    out = []
                    for ch in prim:
                        out.append(("primary", ch))
                    for ch in sec:
                        out.append(("secondary", ch))
                    return out
        except Exception:
            # getConfig may raise if device not ready; ignore and retry
            pass

        time.sleep(poll_interval)

    # Final best-effort: try _localChannels then radioConfig
    local = getattr(iface, "_localChannels", None) or getattr(iface, "localChannels", None)
    if local:
        try:
            out = []
            for ch in list(local):
                out.append(("local", ch))
            return out
        except Exception:
            pass

    rc = getattr(iface, "radioConfig", None)
    if isinstance(rc, dict):
        prim = rc.get("channels") or rc.get("channel") or []
        sec = rc.get("secondaryChannels") or rc.get("secondary") or []
        prim = list(prim) if prim else []
        sec = list(sec) if sec else []
        out = []
        for ch in prim:
            out.append(("primary", ch))
        for ch in sec:
            out.append(("secondary", ch))
        return out
    return []


def main():
    parser = argparse.ArgumentParser(description="Send a test Meshtastic message (auto-detect COM port)")
    parser.add_argument("--port", help="Serial port (e.g. COM3). If omitted the script will try to auto-detect.")
    parser.add_argument("--text", default="Hello World2", help="Text to send")
    parser.add_argument("--channel", default="testRecieve", help="Channel name to send to (e.g. testRecieve)")
    parser.add_argument("--print-config", action="store_true", help="Print raw device config (radioConfig and getConfig()) and exit")
    parser.add_argument("--dump-iface", action="store_true", help="Dump iface dir() and inspect attributes for config/channel info")
    args = parser.parse_args()

    try:
        SERIAL_PORT = find_meshtastic_port(args.port)
    except RuntimeError as e:
        print("Error finding Meshtastic port:", e)
        return

    print(f"Using serial port: {SERIAL_PORT}")

    # Connect to the Meshtastic device
    iface = meshtastic.serial_interface.SerialInterface(SERIAL_PORT)

    # Give it a second to initialize
    time.sleep(1)

    # Optionally print raw configs for debugging
    if args.print_config:
        print("--- radioConfig (cached) ---")
        try:
            pprint.pprint(getattr(iface, "radioConfig", None))
        except Exception as e:
            print("Error reading radioConfig:", e)
        print("--- getConfig() result ---")
        try:
            cfg = iface.getConfig()
            pprint.pprint(cfg)
        except Exception as e:
            print("Error calling getConfig():", e)
        iface.close()
        sys.exit(0)

    if args.dump_iface:
        print("iface dir():")
        attrs = dir(iface)
        pprint.pprint(attrs)
        print('\nInspecting candidate attributes (contain "config" or "channel" or are dict/list):')
        for name in attrs:
            lname = name.lower()
            if 'config' in lname or 'channel' in lname:
                try:
                    val = getattr(iface, name)
                    print(f"--- {name} ---")
                    try:
                        pprint.pprint(val)
                    except Exception:
                        print(repr(val))
                except Exception as e:
                    print(f"Error reading {name}: {e}")

        # Also dump any attribute that is a dict/list for quick inspection
        for name in attrs:
            try:
                val = getattr(iface, name)
            except Exception:
                continue
            if isinstance(val, (dict, list)) and name not in ('__dict__', '__weakref__'):
                print(f"--- {name} (dict/list) ---")
                try:
                    pprint.pprint(val)
                except Exception:
                    print(repr(val))

        iface.close()
        sys.exit(0)

    # Fetch and print available channels from the device
    channels = get_device_channels(iface, timeout=5.0)
    print("Available channels on device:")
    if not channels:
        print("  (no channels discovered)")
    else:
        for i, (origin, ch) in enumerate(channels):
            # extract display name and numeric index if available
            name = None
            num_index = None
            if isinstance(ch, dict):
                name = ch.get("name") or ch.get("label") or ch.get("channelName")
                num_index = ch.get("index")
            else:
                num_index = getattr(ch, "index", None)
                settings = getattr(ch, "settings", None)
                if settings is not None:
                    if isinstance(settings, dict):
                        name = settings.get("name") or settings.get("label")
                    else:
                        name = getattr(settings, "name", None) or getattr(settings, "label", None)
                name = name or getattr(ch, "name", None) or getattr(ch, "label", None)
            idx_display = f" (num_index={num_index})" if num_index is not None else ""
            print(f"  {i} ({origin}): {name}{idx_display}")

    # Require the requested channel to exist; never send on default channel
    # Find the numeric channel index to send on. Prefer numeric index from proto _localChannels if present.
    numeric_index = None
    # Check local/proto channels first for numeric index
    for origin, ch in channels:
        name = None
        num_index = None
        if isinstance(ch, dict):
            name = ch.get("name") or ch.get("label") or ch.get("channelName")
            num_index = ch.get("index")
        else:
            num_index = getattr(ch, "index", None)
            settings = getattr(ch, "settings", None)
            if settings is not None:
                if isinstance(settings, dict):
                    name = settings.get("name") or settings.get("label")
                else:
                    name = getattr(settings, "name", None) or getattr(settings, "label", None)
            name = name or getattr(ch, "name", None) or getattr(ch, "label", None)
        if name and name.lower() == args.channel.lower():
            numeric_index = num_index
            break

    # If we didn't find a numeric index in proto, fall back to find_channel_index which may return numeric index
    if numeric_index is None:
        numeric_index = find_channel_index(iface, args.channel)

    if numeric_index is None:
        print(f"ERROR: Channel '{args.channel}' not found or has no numeric index. Aborting without sending.")
        iface.close()
        sys.exit(1)

    print(f"Sending to channel '{args.channel}' (numeric index {numeric_index})")
    iface.sendText(args.text, channelIndex=numeric_index)
    print(f"Message sent to channel '{args.channel}': {args.text}")

    # Close connection cleanly
    iface.close()


if __name__ == "__main__":
    main()
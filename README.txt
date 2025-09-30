# rednet — Libvirt Network Behind Mullvad VPN

This Bash script automates the creation and management of a **libvirt network** whose traffic is forced through a **Mullvad WireGuard interface** (`wg0-mullvad`).
It configures libvirt, nftables, UFW, and IP forwarding with a **fail-closed** approach to ensure that no VM can bypass the VPN tunnel.

---

## 🚀 Features

* Creates a libvirt NAT network (`rednet`) using `wg0-mullvad` as the outbound interface.
* Defines a **bridge** (`virbr1` by default) providing a private subnet (`10.77.0.0/24`).
* Forces all VM DNS queries to use **Mullvad’s internal DNS** (`10.64.0.1`).
* Sets up **nftables** rules to:

  * Block any traffic outside the VPN.
  * Enforce DNS redirection to the gateway (`10.77.0.1`).
  * Masquerade (NAT) outbound traffic.
* Dynamically updates **UFW** rules to allow traffic between `rednet` and `wg0-mullvad`.
* Enables `ip_forward` only when running, restoring the previous state afterward.
* Starts/stops required **libvirt daemons** on demand.
* Fixes Mullvad’s nftables rules to allow the VM-to-VPN flow if necessary.

---

## 📦 Requirements

The script checks for and uses the following tools:

* `bash` (>= 5, with `set -euo pipefail`)
* `libvirt` + `virsh`
* `systemd` (`systemctl`)
* `nftables`
* `ufw` (optional but recommended)
* `awk`, `sed`, `grep`
* A Mullvad WireGuard interface (`wg0-mullvad`)

---

## ⚙️ Configuration

Main variables (top of the script):

* `NET_NAME="rednet"` → libvirt network name.
* `WG_IF="wg0-mullvad"` → Mullvad WireGuard interface.
* `BR_NAME="virbr1"` → libvirt bridge name.
* `SUBNET_V4="10.77.0.0/24"` → Subnet for VMs.
* `GW_V4="10.77.0.1"` → Gateway (host side).
* `DNS_MULLVAD_INTERNAL="10.64.0.1"` → Forced Mullvad DNS.

---

## ▶️ Usage

```bash
./rednet.sh up      # Create and activate the secure network behind Mullvad
./rednet.sh down    # Tear down the network and restore initial state
./rednet.sh status  # Show the status of the network, nftables, UFW, and ip_forward
```

### Example `up` output:

```
[+] rednet UP  | bridge=virbr1  | GW=10.77.0.1  | NAT via wg0-mullvad
[i] dnsmasq rednet:
server=10.64.0.1
no-resolv
```

---

## 🔒 Security

* **Fail-closed firewall**: if Mullvad goes down, VMs lose connectivity.
* All traffic is **forced through wg0-mullvad**.
* **DNS leak protection** → VMs only resolve through Mullvad DNS.
* UFW and nftables rules are automatically cleaned up on `down`.
* `ip_forward` is restored to its original value after shutdown.

---

## 🛠 Notes

* Designed for **Linux with systemd and libvirt/qemu**.
* Assumes Mullvad is configured through a WireGuard interface called `wg0-mullvad`.
* You can customize names (`NET_NAME`, `WG_IF`, `BR_NAME`) as needed.
* The script also reattaches `vnet*` interfaces to the bridge if they are not already bound.

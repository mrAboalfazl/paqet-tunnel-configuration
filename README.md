Here is a clean, professional, and concise **README.md** for your script.


Here is the updated **Quick Download** section with the commands separated for each file. This allows users to pick exactly which script they need.

---

# 🚀 Paqet-Auto Utility

## 📥 Quick Download & Setup

### 1. Main Configuration Script

Use this for the initial tunnel setup:

```bash
curl -O https://raw.githubusercontent.com/mrAboalfazl/paqet-tunnel-configuration/main/paqetConfigurationTunnel.sh
chmod +x paqetConfigurationTunnel.sh

```

### 2. Automation Script

Use this for managing and decommissioning services:

```bash
curl -O https://raw.githubusercontent.com/mrAboalfazl/paqet-tunnel-configuration/main/paqet-auto.sh
chmod +x paqet-auto.sh

```

---

## 🔧 Usage Examples

### 1. Standard Execution

Run the script based on your server location (Iran or Abroad).

* **Iran Client (All udp2raw):**
```bash
./paqet-auto.sh --mode=iran

```


* **Abroad Server (Main udp2raw):**
```bash
./paqet-auto.sh --mode=kharej

```



### 2. Targeting Specific Services

Use the `--only` flag to act on a single service.

* **Single Service (Iran):**
```bash
./paqet-auto.sh --mode=iran --only=udp2raw5186

```


* **Custom Service Name (Abroad):**
```bash
./paqet-auto.sh --mode=kharej --only=my-udp2raw-server

```



### 3. Decommissioning & Cleanup

Stop services and disable related Cron jobs permanently.

| Target | Command |
| --- | --- |
| **Iran (Remove udp2raw)** | `./paqet-auto.sh --mode=iran --decommission-udp2raw=yes` |
| **Abroad (Remove udp2raw)** | `./paqet-auto.sh --mode=kharej --decommission-udp2raw=yes` |
| **Abroad (Remove Backhaul)** | `./paqet-auto.sh --mode=kharej --decommission-backhaul=yes` |

**Full Cleanup (Both Services):**

```bash
./paqet-auto.sh --mode=iran --decommission-udp2raw=yes --decommission-backhaul=yes

```

---

## 💡 Pro Tip: Dry Run

To test the script without making any actual changes (simulation mode), add the `--dry-run` flag:

```bash
./paqet-auto.sh --mode=iran --dry-run

```

---

Would you like me to add a section explaining how to verify if the services are running correctly after using these commands?



---

# 🚀 Paqet-Auto Utility

A lightweight automation script to manage `udp2raw` and `backhaul` services with ease. Use the following flags to automate deployment, maintenance, or decommissioning.

## 🔧 Usage Examples

### 1. Standard Execution

Run the script based on your server location (Iran or Abroad).

* **Iran Client (All udp2raw):**
```bash
./paqet-auto.sh --mode=iran

```


* **Abroad Server (Main udp2raw):**
```bash
./paqet-auto.sh --mode=kharej

```



---

### 2. Targeting Specific Services

Use the `--only` flag to act on a single service instead of all of them.

* **Single Service (Iran):**
```bash
./paqet-auto.sh --mode=iran --only=udp2raw5186

```


* **Custom Service Name (Abroad):**
```bash
./paqet-auto.sh --mode=kharej --only=my-udp2raw-server

```



---

### 3. Decommissioning & Cleanup

Stop services and disable related Cron jobs permanently.

| Target | Command |
| --- | --- |
| **Iran (Remove udp2raw)** | `./paqet-auto.sh --mode=iran --decommission-udp2raw=yes` |
| **Abroad (Remove udp2raw)** | `./paqet-auto.sh --mode=kharej --decommission-udp2raw=yes` |
| **Abroad (Remove Backhaul)** | `./paqet-auto.sh --mode=kharej --decommission-backhaul=yes` |

**Full Cleanup (Both Services):**

```bash
./paqet-auto.sh --mode=iran --decommission-udp2raw=yes --decommission-backhaul=yes

```

---

## 💡 Pro Tip: Dry Run

If you want to test the script without making any actual changes (simulation mode), add the `--dry-run` flag:

```bash
./paqet-auto.sh --mode=iran --dry-run

```

*This will only log the actions to the console without executing `systemctl` or modifying files.*

---

# Brigaider 🍏🪟

**Brigaider** is a modern, lightning-fast Go port of the classic **Brigadier** utility. It allows you to download, extract, and install Apple Boot Camp drivers and support software directly on Windows machines using official Apple Software Update catalogs (`.sucatalog`).

---

## Features

* **⚡ Blazing Fast:** Written entirely in Go for instant execution and minimal resource overhead.
* **🔒 Mac Model Validation:** Features built-in model verification to ensure target identifiers strictly conform to Apple nomenclature (e.g., `MacBookAir6,2`, `MacBookPro11,1`).
* **📦 Automated Extraction & Setup:** Seamlessly integrates with 7-Zip to unpack Apple payload archives and automate MSI installation.
* **⌨️ Post-Install Tweaks:** Automatically injects registry keys (such as Apple Keyboard Support `FirstTimeRun`) for a smooth out-of-the-box experience.

---

## Requirements

* **Operating System:** Windows 64-bit (`amd64`) for installation routines.
* **Dependencies:** 7-Zip installed in its default path (`C:\Program Files\7-Zip\7z.exe`).

---

## Usage & Command-Line Flags
Brigaider automatically works out of the box if you type brigadier.exe
```bash
brigaider.exe

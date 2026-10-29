# NexGen Metadata — Local Web Forensic Suite

NexGen Metadata is an offline-first, high-throughput digital forensics and metadata extraction engine built with **Rust (Axum + Rayon + Tokio + SQLite)** and **React 18 (Vite + TanStack Virtual + dnd-kit)**.

---

## Prerequisites

1. **Rust Toolchain:** Stable Rust 1.80+ (`cargo`, `rustc`)
2. **Node.js:** Node 18+ & npm
3. **ExifTool Binary:** `exiftool.exe` (Windows) or `exiftool` (Linux/macOS)

---

## Setup & Build Instructions

### Step 1: Install ExifTool Binary
NexGen Metadata utilizes a persistent daemon pool of ExifTool workers. Place `exiftool.exe` directly in the backend target directory or ensure it exists on your system `PATH`:

```powershell
# Option A: Place in working directory / binary folder
Copy-Item "C:\path\to\exiftool.exe" ".\src-tauri\exiftool.exe"

# Option B: Add to Windows System PATH
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\ExifTool", [EnvironmentVariableTarget]::User)
```

---

### Step 2: Build the React Frontend
Compile the production frontend assets to `./dist`:

```powershell
# In project root
npm install
npm run build
```

This compiles all React components, icons, and virtualized tables into `./dist`.

---

### Step 3: Generate the Master License Keys
Run the cryptographic license generator to create your master Ed25519 signing key and generate customer activation keys:

```powershell
cd src-tauri

# Generate keypair and issue a 365-day license key for a customer:
cargo run --bin generate_license -- "Case-Officer-Smith" 365
```

**Output:**
1. Generates `nexgen_private.key` (keep secret at HQ).
2. Generates `nexgen_public.key`.
3. Outputs the customer key:
   ```
   >>> LICENSE KEY TO SEND TO CUSTOMER <<<
   NEXGEN-eyJjdXN0b21lcl9pZCI6... .wJ9f8dK2...
   ```

*Note: The public key is already hardcoded into `src/auth.rs`. If you generate a new master keypair, update `EMBEDDED_PUBLIC_KEY` in `src/auth.rs` with the 32-byte public key array printed by the tool.*

---

### Step 4: Run the Local Web Server

```powershell
cd src-tauri
cargo run --release --bin nexgen-server
```

The server binds strictly to **`http://127.0.0.1:8080`**:
* **Access URL:** Open your browser and navigate to `http://127.0.0.1:8080`.
* **Zero-CORS:** Frontend and backend run on the same port.
* **Strict Localhost:** Rejects external network interfaces (`0.0.0.0`).

---

### Step 5: Activation & Usage

1. Open `http://127.0.0.1:8080`.
2. Paste your `NEXGEN-XXXX...` key into the license gate and click **Activate & Launch Engine**.
3. Specify your target folder path (e.g. `C:\Evidence\Drive_01`).
4. Select desired metadata categories or fields and arrange output column order.
5. Click **Start Scan** — watch real-time progress via Server-Sent Events (SSE) and review records in the virtualized preview table.
6. Click **CSV**, **Excel (.xlsx)**, or **JSON** to download your dataset along with its cryptographic BLAKE3 manifest (`nexgen_manifest.json`).

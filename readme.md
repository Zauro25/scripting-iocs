# Jawaban Bagian D - Scripting & Automation

## 1. Project Overview

Project ini terdiri dari dua script Python untuk membantu proses IOC enrichment dan endpoint triage.

| File | Description |
|---|---|
| `enrichment.py` | Memvalidasi dan melakukan enrichment IOC menggunakan VirusTotal API. |
| `triage_collector.py` | Mengumpulkan informasi dari host Windows yang dicurigai terkompromi. |

## 2. Requirements

- Python 3
- Windows untuk menjalankan triage collector.
- Koneksi internet untuk IOC enrichment.
- VirusTotal API Key untuk enrichment VirusTotal.
- Hak Administrator untuk menjalankan triage collector di Windows.

Install dependency:

```bash
pip install requests
```

## 3. How to Run

### A. IOC Enrichment

Atur VirusTotal API Key melalui environment variable.

Windows PowerShell:

```powershell
$env:VT_API_KEY="YOUR_API_KEY"
```

Linux/macOS:

```bash
export VT_API_KEY="YOUR_API_KEY"
```

Jalankan:

```bash
python enrichment.py
```

Script membaca `iocs.txt`, memvalidasi setiap IOC, lalu mengirimkan IOC valid ke VirusTotal API.
Mode normal membutuhkan `VT_API_KEY`. Mode mock hanya digunakan secara eksplisit dengan `python enrichment.py --mock`.

Hasil enrichment disimpan dalam:

- `results.json`
- `results.csv`

Informasi hasil enrichment meliputi IOC, tipe IOC, skor reputasi, dan verdict.

Verdict ditentukan berdasarkan hasil analisis VirusTotal:

- `malicious`: Terdapat deteksi malicious.
- `suspicious`: Terdapat deteksi suspicious tanpa deteksi malicious.
- `clean`: Tidak terdapat deteksi malicious maupun suspicious pada hasil analisis yang tersedia.
- `unknown`: IOC tidak ditemukan atau enrichment gagal.

Skor reputasi dihitung berdasarkan persentase deteksi malicious terhadap total hasil analisis. Skor tersebut merupakan perhitungan sederhana, bukan skor resmi VirusTotal.

### B. Triage Collector

Jalankan script pada host Windows yang dicurigai terkompromi menggunakan hak Administrator.

```bash
python triage_collector.py
```

Script mengumpulkan:

1. Running processes beserta command line.
2. Koneksi jaringan TCP dan UDP endpoint.
3. Registry autorun pada Run dan RunOnce.
4. Informasi user yang sedang login.

Hasil pengumpulan disimpan dalam folder dengan format timestamp.

Contoh struktur output:

```text
triage_20261108_170000/
├── processes.txt
├── network.txt
├── autoruns.txt
├── logged_users.txt
└── hashes.txt
```

File `hashes.txt` berisi nilai SHA256 dari setiap file hasil pengumpulan.

## 4. Assumptions and Limitations

1. IOC enrichment menggunakan VirusTotal API v3 dan membutuhkan `VT_API_KEY`, kecuali saat mode mock dipilih eksplisit.
2. Enrichment membutuhkan koneksi internet dan mengikuti batas penggunaan API.
3. IOC yang tidak valid akan dilewati dan tidak dikirim ke VirusTotal.
4. IOC yang tidak ditemukan atau gagal diperiksa akan memiliki verdict `unknown`, bukan dianggap clean.
5. Triage collector ditujukan untuk sistem operasi Windows; pada OS lain, file tetap dibuat tetapi berisi error command yang tidak tersedia.
6. Pengumpulan registry mencakup registry pengguna yang sedang login dan registry mesin, bukan seluruh profil pengguna.
7. Informasi UDP yang dikumpulkan berupa endpoint lokal, sedangkan koneksi TCP mencakup alamat dan port tujuan.
8. Triage collector hanya mengumpulkan informasi dan tidak mengubah konfigurasi sistem atau melakukan containment.
9. File `hashes.txt` berisi hash file hasil pengumpulan lainnya, bukan hash dirinya sendiri.

## 5. SOAR Playbook Design - Suspicious PowerShell

### Trigger

Playbook dijalankan ketika SIEM atau EDR menghasilkan alert `Suspicious PowerShell` pada suatu endpoint.

Alert tersebut dapat berisi informasi host, username, process ID, command line, dan waktu kejadian.

### Automated Steps

1. SOAR menerima alert dan mengambil informasi endpoint serta detail proses PowerShell.
2. SOAR menjalankan `triage_collector.py` pada endpoint terkait melalui integrasi EDR atau remote execution.
3. Triage collector mengumpulkan proses berjalan, koneksi jaringan, registry autorun, dan user yang sedang login.
4. SOAR mengambil hasil triage dan mengekstrak IOC yang ditemukan.
5. IOC dikirim ke `enrichment.py` untuk diperiksa melalui VirusTotal.
6. SOAR menggabungkan hasil enrichment dengan informasi alert dan hasil triage.

### Human Decision Point

Hasil investigasi ditampilkan kepada analis SOC untuk diperiksa.

Analis mengevaluasi command line PowerShell, proses yang berjalan, koneksi jaringan, registry autorun, dan reputasi IOC.

Jika ditemukan indikasi kompromi, analis menentukan tindakan lanjutan seperti isolasi endpoint, pemblokiran IOC, atau penonaktifan akun terkait.

Tindakan containment dilakukan setelah mendapatkan persetujuan analis agar tidak mengganggu sistem yang masih dibutuhkan untuk operasional bisnis.

### Ticket Output

SOAR membuat atau memperbarui tiket investigasi yang berisi:

- Alert ID dan waktu kejadian.
- Host dan user yang terdampak.
- Detail proses PowerShell dan command line.
- Hasil triage collector.
- Daftar IOC dan hasil enrichment.
- SHA256 file hasil pengumpulan.
- Hasil analisis dan keputusan analis.
- Tindakan containment yang telah diset

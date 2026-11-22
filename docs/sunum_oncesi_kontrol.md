# Sunum öncesi kontrol listesi

Amaç: sunumda ekranlarda test kalıntısı olmasın, sayılar güncel olsun, her şey çevrimdışı da çalışsın.

## Denetim kaydındaki eski test satırları hakkında

Testler artık ayrı bir veritabanında (`ThreatLens_Test`) çalışır; canlı `ThreatLens` veritabanına yazmazlar (`tests/test_zz_live_guard.py` bunu her test çalışmasında doğrular). Ayrımdan **önce** canlı veritabanına yazılmış test kayıtları iki türdür:

| Kayıt | Silinebilir mi | Ne yapılır |
|---|---|---|
| Log avları, giriş denemeleri, kanıtlar, etiketler | Evet | `python scripts/purge_test_artifacts.py` (önce rapor), sonra `--apply` |
| Denetim kaydı (`dbo.AuditLog`) | **Hayır** (`trg_AuditLog_Protect` tasarım gereği engeller) | (b) arayüz filtresi ya da (a) temiz kurulum |

İki yol vardır; ikisi birlikte de kullanılabilir.

### (b) Arayüz filtresi (varsayılan, veri silmez)

Denetim kayıtları ekranında **"Otomasyon kayıtlarını gizle"** kutusu varsayılan olarak işaretlidir. Gizlenenler:
- içeriğinde test desenleri geçen kayıtlar (`pytest`, `*.example`, `*.test`, `CVE-2099-*`, `namekey-*`),
- RFC 5737 belgeleme IP bloklarındaki IOC'ler (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
- 5 dakika içinde eklenip silinen kısa ömürlü kayıtlar,
- giriş denemelerinde test istemcisi (`testclient`) ve `pytest-*` kullanıcı adları.

Kutunun yanında gizlenen kayıt sayısı yazar; işaret kaldırılınca hepsi görünür. Hiçbir satır silinmez.

### (a) Temiz kurulum (her şey sıfırdan)

**Dikkat: bu yol canlı veritabanını SİLER** (vakalar, notlar, tespit kapsamı işaretleri, kurum içi görülmeler dahil). Saklamak istediğiniz bir şey varsa önce yedek alın.

1. Uygulamayı durdurun (`run.py` penceresi).
2. Yedek: SSMS'te ya da `sqlcmd` ile `EXEC ThreatLens.dbo.sp_BackupDatabase;` (yedek `...\MSSQL\Backup\ThreatLens_gunN.bak`).
3. Temiz kurulum ve beslemeler:
   ```powershell
   .venv\Scripts\python scripts\setup_db.py --reset
   ```
   `--reset` veritabanını silip yeniden kurar, ATT&CK anlık görüntüsünü yükler ve beslemeleri (CISA KEV, abuse.ch, Malpedia) yeniden çeker. Süre: birkaç dakika. abuse.ch anahtarı `.env` dosyasında olmalı.
4. IP aralıkları (isteğe bağlı): Veri kaynakları → iptoasn.com → Senkronize et (yönetici).
5. Uygulamayı başlatın: `.venv\Scripts\python run.py`.

## Sunum günü kontrolleri

- [ ] `python -m pytest -q` → tümü geçti, `test_live_database_untouched` geçti.
- [ ] `python scripts/purge_test_artifacts.py` → toplam 0 (gerekirse `--apply`).
- [ ] Genel bakışta "Son besleme senkronu" son 6 saat içinde; değilse Veri kaynakları → Senkronize et.
- [ ] Denetim kayıtları ekranında "Otomasyon kayıtlarını gizle" işaretli.
- [ ] Kullanıcı menüsü → **Geliştirici modu: açık** (SQL düğmesi ve görünüm/yordam adları sunumda görünür).
- [ ] Tarayıcı yakınlaştırması %100, pencere 1440 CSS px genişlikte (ekran ölçeği %200 ise tam ekran).
- [ ] İnternet bağlantısı olmadan da arayüz açılıyor mu (kütüphaneler `app/static/vendor/` altında): kablosuzu kapatıp bir sayfayı yenileyin.
- [ ] `.env` dosyasında `TL_LOGIN_HINT` yok ya da `0` (giriş ekranında kullanıcı adları görünmez).
- [ ] Demo betikleri (SSMS): `database/demos/demo1..8` sırayla, Demo 6 için iki pencere.

# API uç noktaları (otomatik üretildi)

> `python scripts/gen_docs.py` ile FastAPI OpenAPI şemasından üretilmiştir. Etkileşimli belge: http://127.0.0.1:8000/api/docs

Kimlik doğrulama: `POST /api/auth/login` oturum çerezi (`tl_session`, HttpOnly) verir. Roller: **İzleyici** okur; **Analist** IOC, ilişki ve içe aktarma yazar; **Yönetici** ek olarak kullanıcıları ve ATT&CK yüklemesini yönetir.
Hatalar her zaman `{"detail": "..."}` biçimindedir: 400 iş kuralı (T-SQL THROW 50001-50099), 401 oturum yok, 403 yetki yok, 404 bulunamadı, 409 benzersizlik/yabancı anahtar, 422 alan doğrulama, 503 veritabanına ulaşılamıyor.

## auth

| Yöntem | Yol | Açıklama | Parametreler |
|---|---|---|---|
| POST | `/api/auth/login` | Login | gövde (JSON / form) |
| POST | `/api/auth/logout` | Logout |  |
| GET | `/api/auth/me` | Me |  |

## dashboard

| Yöntem | Yol | Açıklama | Parametreler |
|---|---|---|---|
| GET | `/api/meta` | Form ve filtrelerde kullanılan sözlük tabloları. |  |
| GET | `/api/dashboard/summary` | Dashboard Summary | `days` |
| GET | `/api/search` | Üst bardaki global arama: sp_GlobalSearch (IOC, aktör, zararlı, kampanya, teknik, CVE). | `q` |
| GET | `/api/trace/{trace_id}` | Arayüzdeki 'SQL' çekmecesi: bir isteğin çalıştırdığı gerçek T-SQL ifadeleri. | `trace_id` |

## iocs

| Yöntem | Yol | Açıklama | Parametreler |
|---|---|---|---|
| GET | `/api/iocs` | List Iocs | `q`, `type`, `severity`, `source`, `status`, `malware`, `tag`, `minConfidence`, `maxConfidence`, `dateFrom`, `dateTo`, `sort`, `dir`, `page`, `size` |
| POST | `/api/iocs` | Create Ioc | gövde (JSON / form) |
| POST | `/api/iocs/lookup` | Yapıştırılan IOC listesinden hangileri kayıtlı? Değerler önce Python'da normalleştirilir. | gövde (JSON / form) |
| GET | `/api/iocs/{indicator_id}` | Get Ioc | `indicator_id` |
| PUT | `/api/iocs/{indicator_id}` | Update Ioc | `indicator_id` + gövde (JSON / form) |
| DELETE | `/api/iocs/{indicator_id}` | Delete Ioc | `indicator_id` |
| GET | `/api/iocs/{indicator_id}/relationships` | Göstergenin ilişkileri SQL Graph üzerinden: MATCH tabanlı vw_IndicatorAttribution ve çok adımlı | `indicator_id` |
| POST | `/api/iocs/{indicator_id}/sightings` | Add Sighting | `indicator_id` + gövde (JSON / form) |

## graph

| Yöntem | Yol | Açıklama | Parametreler |
|---|---|---|---|
| GET | `/api/graph/search` | Aranan değeri graf düğümüne çözer. IOC'ye benziyorsa önce normalleştirilip birebir aranır; | `q` |
| GET | `/api/graph/neighborhood` | sp_GetNeighborhood: başlangıç düğümünden genişlik öncelikli gezinme (en çok `limit` düğüm). | `type`, `id`, `depth`, `limit`, `techniques`, `indicators` |
| GET | `/api/graph/node` | Seçili düğümün özeti (sağ panel). | `type`, `id` |
| GET | `/api/graph/edge` | Kenar detayı: ilişki türü, güven puanı, kanıt metni ve doğrulama kaynağı. | `sourceType`, `sourceId`, `targetType`, `targetId`, `relation` |
| GET | `/api/graph/path` | İki aktör arasındaki en kısa 'ortak araç' zinciri (SHORTEST_PATH, ağırlıksız). | `fromActor`, `toActor`, `maxHops` |
| GET | `/api/graph/stats` | Graf tablolarının satır sayıları ve ilişkisel modelle tutarlılığı (sp_CheckGraphConsistency). |  |

## entities

| Yöntem | Yol | Açıklama | Parametreler |
|---|---|---|---|
| GET | `/api/actors` | List Actors | `q`, `country`, `motivation`, `sector`, `sort`, `page`, `size` |
| POST | `/api/actors` | Create Actor | gövde (JSON / form) |
| GET | `/api/actors/{actor_id}` | Get Actor | `actor_id` |
| PUT | `/api/actors/{actor_id}` | Update Actor | `actor_id` + gövde (JSON / form) |
| DELETE | `/api/actors/{actor_id}` | Delete Actor | `actor_id` |
| GET | `/api/malware` | List Malware | `q`, `type`, `linked`, `sort`, `page`, `size` |
| POST | `/api/malware` | Create Malware | gövde (JSON / form) |
| GET | `/api/malware/{malware_id}` | Get Malware | `malware_id` |
| PUT | `/api/malware/{malware_id}` | Update Malware | `malware_id` + gövde (JSON / form) |
| DELETE | `/api/malware/{malware_id}` | Delete Malware | `malware_id` |
| GET | `/api/campaigns` | List Campaigns | `q`, `ongoing`, `actor`, `page`, `size` |
| POST | `/api/campaigns` | Create Campaign | gövde (JSON / form) |
| GET | `/api/campaigns/{campaign_id}` | Get Campaign | `campaign_id` |
| PUT | `/api/campaigns/{campaign_id}` | Update Campaign | `campaign_id` + gövde (JSON / form) |
| DELETE | `/api/campaigns/{campaign_id}` | Delete Campaign | `campaign_id` |
| GET | `/api/vulnerabilities` | List Vulnerabilities | `q`, `kev`, `page`, `size` |
| POST | `/api/vulnerabilities` | Create Vulnerability | gövde (JSON / form) |
| GET | `/api/vulnerabilities/{vulnerability_id}` | Get Vulnerability | `vulnerability_id` |
| PUT | `/api/vulnerabilities/{vulnerability_id}` | Update Vulnerability | `vulnerability_id` + gövde (JSON / form) |
| DELETE | `/api/vulnerabilities/{vulnerability_id}` | Delete Vulnerability | `vulnerability_id` |
| POST | `/api/links` | İlişki ekler. Kanıtsız ilişki kurulamaz: önce Evidence satırı, sonra ara tablo satırı yazılır (tek transaction). | gövde (JSON / form) |
| DELETE | `/api/links` | Remove Link | `kind`, `a`, `b` |

## attack

| Yöntem | Yol | Açıklama | Parametreler |
|---|---|---|---|
| GET | `/api/tactics` | Taktik kartları: her taktikteki teknik sayısı ve bu tekniklerden en az bir aktörün kullandığı sayı. |  |
| GET | `/api/techniques` | List Techniques | `q`, `tactic`, `actor`, `campaign`, `malware`, `subtechniques`, `sort`, `page`, `size` |
| GET | `/api/techniques/{technique_id}` | Technique Detail | `technique_id` |
| GET | `/api/attack/matrix` | Attack Matrix | `actor`, `malware`, `campaign` |

## admin

| Yöntem | Yol | Açıklama | Parametreler |
|---|---|---|---|
| GET | `/api/sources` | Kaynak sağlığı (vw_SourceHealth) ve son 7 günün iş özeti. |  |
| GET | `/api/imports` | List Imports | `source`, `status`, `page`, `size` |
| POST | `/api/imports` | CSV/JSON dosyasından gösterge içe aktarma. Katı modda (strict) tek hatalı satır tüm dosyayı geri alır. | gövde (JSON / form) |
| GET | `/api/imports/{job_id}` | Get Import | `job_id` |
| POST | `/api/imports/feed` | Bir beslemeyi elle senkronize eder. abuse.ch anahtarı yoksa iş açılmaz, açık bir mesaj döner. | gövde (JSON / form) |
| GET | `/api/audit-logs` | Audit Logs | `table`, `action`, `user`, `record`, `dateFrom`, `dateTo`, `page`, `size` |
| GET | `/api/audit-logs/stats` | Audit Stats |  |
| GET | `/api/users` | Users |  |
| POST | `/api/users` | Create User | gövde (JSON / form) |
| PATCH | `/api/users/{user_id}` | Update User | `user_id` + gövde (JSON / form) |
| GET | `/api/system` | Ayarlar ekranı: sunucu sürümü, veritabanı nesne sayıları, graf tutarlılığı, entegrasyon durumu. |  |

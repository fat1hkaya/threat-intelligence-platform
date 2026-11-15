NODES = [("IndicatorNode","IndicatorID","BIGINT","Indicator","indicator"),("MalwareNode","MalwareID","INT","Malware","malware"),
         ("ActorNode","ActorID","INT","ThreatActor","actor"),("CampaignNode","CampaignID","INT","Campaign","campaign"),
         ("TechniqueNode","TechniqueID","INT","Technique","technique"),("VulnerabilityNode","VulnerabilityID","INT","Vulnerability","vulnerability")]
N = {n[4]: n for n in NODES}
# kenar, kaynak, hedef, ilişki, ilişkisel tablo, kaynak sütun, hedef sütun, ek koşul, güven sütunu, kanıt sütunu
EDGES = [
 ("IndicatesMalware","indicator","malware","indicates","dbo.MalwareIndicator","IndicatorID","MalwareID","","x.Confidence","x.EvidenceID"),
 ("ActorUsesMalware","actor","malware","uses","dbo.ActorMalware","ActorID","MalwareID","","x.Confidence","x.EvidenceID"),
 ("ActorUsesTechnique","actor","technique","uses","dbo.ActorTechnique","ActorID","TechniqueID","","x.Confidence","x.EvidenceID"),
 ("MalwareUsesTechnique","malware","technique","uses","dbo.MalwareTechnique","MalwareID","TechniqueID","","x.Confidence","x.EvidenceID"),
 ("MalwareExploitsVulnerability","malware","vulnerability","exploits","dbo.MalwareVulnerability","MalwareID","VulnerabilityID","","x.Confidence","x.EvidenceID"),
 ("CampaignAttributedToActor","campaign","actor","attributed-to","dbo.Campaign","CampaignID","ActorID"," AND x.ActorID IS NOT NULL","CAST(NULL AS TINYINT)","x.AttributionEvidenceID"),
 ("CampaignUsesMalware","campaign","malware","uses","dbo.CampaignMalware","CampaignID","MalwareID","","x.Confidence","x.EvidenceID"),
 ("CampaignUsesTechnique","campaign","technique","uses","dbo.CampaignTechnique","CampaignID","TechniqueID","","x.Confidence","x.EvidenceID"),
 ("CampaignContainsIndicator","campaign","indicator","observed","dbo.CampaignIndicator","CampaignID","IndicatorID","","x.Confidence","x.EvidenceID"),
]
o=[]; w=o.append
w(open(__file__.replace("gen_graph.py","header.sql"),encoding="utf-8").read())
w("/* ---------- 1. Düğüm tabloları ----------\n   Her düğüm, ilişkisel kaydının anahtarını benzersiz olarak taşır (1:1 eşleme). */\n")
for t,k,typ,rel,_ in NODES:
    w(f"CREATE TABLE dbo.{t} (\n    {k} {typ} NOT NULL CONSTRAINT UQ_{t}_{k} UNIQUE\n) AS NODE;\n")
w("GO\n\n/* ---------- 2. Kenar tabloları ----------\n   Yön: gösterge -> zararlı, aktör -> zararlı/teknik, zararlı -> teknik/zafiyet, kampanya -> aktör/zararlı/teknik/gösterge.\n"
  "   Confidence ve EvidenceID, ilişkisel ara tablodaki değerlerin yansımasıdır (ilişki detay panelinde gösterilir).\n"
  "   Kenar kısıtı (CONNECTION): yanlış tipte iki düğüm bağlanamaz; düğüm silinince kenarı da silinir. */\n")
for e,s,t,rn,*_ in EDGES:
    role = "    Role       VARCHAR(12)  NOT NULL CONSTRAINT DF_IndicatesMalware_Role DEFAULT ('other'),\n" if e=="IndicatesMalware" else ""
    w(f"CREATE TABLE dbo.{e} (\n{role}    Confidence TINYINT NULL,\n    EvidenceID INT NULL,\n"
      f"    CreatedAt  DATETIME2(0) NOT NULL CONSTRAINT DF_{e}_CreatedAt DEFAULT (SYSUTCDATETIME()),\n"
      f"    CONSTRAINT EC_{e} CONNECTION (dbo.{N[s][0]} TO dbo.{N[t][0]}) ON DELETE CASCADE\n) AS EDGE;\n")
w('''
/* Türetilmiş kenar: en az 3 ortak zararlı yazılım/araç kullanan iki aktör (iki yönde).
   SHORTEST_PATH için tek tip düğüm ve kenar gerekir; aktörler arası yol bu kenar üzerinden aranır. */
CREATE TABLE dbo.ActorSharesToolsWith (
    SharedCount INT NOT NULL,
    CONSTRAINT CK_ActorSharesToolsWith_SharedCount CHECK (SharedCount >= 3),
    CONSTRAINT EC_ActorSharesToolsWith CONNECTION (dbo.ActorNode TO dbo.ActorNode) ON DELETE CASCADE
) AS EDGE;
GO

/* $from_id / $to_id için varsayılan indeks yoktur; iki yönde gezinme için eklenir */
''')
for e,*_ in EDGES+[("ActorSharesToolsWith",)]:
    w(f"CREATE UNIQUE NONCLUSTERED INDEX UX_{e}_FromTo ON dbo.{e} ($from_id, $to_id);\nCREATE NONCLUSTERED INDEX IX_{e}_To ON dbo.{e} ($to_id);\n")
w("GO\n\n/* ---------- 3. MATCH tabanlı görünümler ---------- */\n\n/* vw_GraphEdge: tüm kenar tipleri MATCH ile okunup tek biçimde birleştirilir.\n   İlişki grafı ekranı (sp_GetNeighborhood) kenarları buradan okur. */\nCREATE OR ALTER VIEW dbo.vw_GraphEdge\nAS\n")
parts=[]
for e,s,t,rn,*_ in EDGES:
    a,b=N[s],N[t]
    parts.append(f"SELECT '{s}' AS SourceType, CAST(a.{a[1]} AS BIGINT) AS SourceID, '{t}' AS TargetType, CAST(b.{b[1]} AS BIGINT) AS TargetID,\n"
                 f"       '{rn}' AS Relation, e.Confidence, e.EvidenceID\nFROM dbo.{a[0]} AS a, dbo.{e} AS e, dbo.{b[0]} AS b\nWHERE MATCH(a-(e)->b)")
w("\nUNION ALL\n".join(parts)+";\nGO\n")
w(open(__file__.replace("gen_graph.py","middle.sql"),encoding="utf-8").read())
for t,k,typ,rel,_ in NODES:
    w(f"        DELETE n FROM dbo.{t} AS n WHERE NOT EXISTS (SELECT 1 FROM dbo.{rel} AS r WHERE r.{k} = n.{k});\n"
      f"        INSERT INTO dbo.{t} ({k})\n        SELECT r.{k} FROM dbo.{rel} AS r WHERE NOT EXISTS (SELECT 1 FROM dbo.{t} AS n WHERE n.{k} = r.{k});\n\n")
w("        /* 4.2 Kenarlar. MATCH yalnızca SELECT içinde kullanılabildiği için önce mevcut kenarlar\n"
  "           MATCH ile #cur tablosuna okunur, ardından değişiklikler $edge_id üzerinden yapılır. */\n"
  "        CREATE TABLE #cur (EdgeID NVARCHAR(1000) NOT NULL, FromKey BIGINT NOT NULL, ToKey BIGINT NOT NULL,\n"
  "                           Role VARCHAR(12) NULL, Confidence TINYINT NULL, EvidenceID INT NULL);\n\n")
for e,s_,t,rn,src,sc,tc,extra,conf,ev in EDGES:
    a_,b_=N[s_],N[t]
    role = e=="IndicatesMalware"
    rsel = "e.Role" if role else "NULL"
    w(f"        -- {e}: {s_} -> {t}\n        TRUNCATE TABLE #cur;\n"
      f"        INSERT INTO #cur (EdgeID, FromKey, ToKey, Role, Confidence, EvidenceID)\n"
      f"        SELECT e.$edge_id, a.{a_[1]}, b.{b_[1]}, {rsel}, e.Confidence, e.EvidenceID\n"
      f"        FROM dbo.{a_[0]} AS a, dbo.{e} AS e, dbo.{b_[0]} AS b\n        WHERE MATCH(a-(e)->b);\n\n"
      f"        DELETE FROM dbo.{e}\n        WHERE $edge_id IN (SELECT c.EdgeID FROM #cur AS c\n"
      f"                           WHERE NOT EXISTS (SELECT 1 FROM {src} AS x WHERE x.{sc} = c.FromKey AND x.{tc} = c.ToKey{extra}));\n\n")
    cols = "$from_id, $to_id, " + ("Role, " if role else "") + "Confidence, EvidenceID"
    vals = "a.$node_id, b.$node_id, " + ("x.Role, " if role else "") + f"{conf}, {ev}"
    w(f"        INSERT INTO dbo.{e} ({cols})\n        SELECT {vals}\n        FROM {src} AS x\n"
      f"        JOIN dbo.{a_[0]} AS a ON a.{a_[1]} = x.{sc}\n        JOIN dbo.{b_[0]} AS b ON b.{b_[1]} = x.{tc}\n"
      f"        WHERE NOT EXISTS (SELECT 1 FROM #cur AS c WHERE c.FromKey = x.{sc} AND c.ToKey = x.{tc});\n\n")
    sets = ("Role = x.Role, " if role else "") + f"Confidence = {conf}, EvidenceID = {ev}"
    cmp_r = ("x.Role" if role else "NULL") + f", {conf}, {ev}"
    w(f"        UPDATE e SET {sets}\n        FROM dbo.{e} AS e\n        JOIN #cur AS c ON c.EdgeID = e.$edge_id\n"
      f"        JOIN {src} AS x ON x.{sc} = c.FromKey AND x.{tc} = c.ToKey\n"
      f"        WHERE EXISTS (SELECT c.Role, c.Confidence, c.EvidenceID EXCEPT SELECT {cmp_r});\n\n")
w("        DROP TABLE #cur;\n\n")
w(open(__file__.replace("gen_graph.py","tail1.sql"),encoding="utf-8").read())
rows=[]
for t,k,typ,rel,_ in NODES:
    rows.append(f"        SELECT '{t}' AS ObjectName, 'node' AS Kind, (SELECT COUNT(*) FROM dbo.{rel}) AS Relational, (SELECT COUNT(*) FROM dbo.{t}) AS Graph")
for e,s,t,rn,src,sc,tc,extra,*_ in EDGES:
    cond=f" WHERE {extra[5:]}" if extra else ""
    rows.append(f"        SELECT '{e}', 'edge', (SELECT COUNT(*) FROM {src} AS x{cond}), (SELECT COUNT(*) FROM dbo.{e})")
w("\n        UNION ALL\n".join(rows))
w(open(__file__.replace("gen_graph.py","tail2.sql"),encoding="utf-8").read())
w("\n/* ---------- 6. Eşleme tetikleyicileri: ilişkisel değişiklik -> graf (aynı transaction) ----------\n"
  "   Kenar silme, düğüm tablolarıyla $from_id/$to_id karşılaştırarak yapılır (MATCH yalnızca SELECT'te kullanılabilir). */\n")
for t,k,typ,rel,_ in NODES:
    w(f"CREATE OR ALTER TRIGGER dbo.trg_{rel}_GraphNode ON dbo.{rel} AFTER INSERT, DELETE\nAS\nBEGIN\n    SET NOCOUNT ON;\n"
      f"    DELETE n FROM dbo.{t} AS n JOIN deleted AS d ON d.{k} = n.{k};      -- kenarları ON DELETE CASCADE ile gider\n"
      f"    INSERT INTO dbo.{t} ({k}) SELECT i.{k} FROM inserted AS i\n"
      f"    WHERE NOT EXISTS (SELECT 1 FROM dbo.{t} AS n WHERE n.{k} = i.{k});\nEND;\nGO\n"
      f"-- Aynı tablodaki kenar tetikleyicisinden önce çalışmalı (önce düğüm, sonra kenar)\n"
      f"EXEC sp_settriggerorder @triggername = N'dbo.trg_{rel}_GraphNode', @order = N'First', @stmttype = N'INSERT';\nGO\n")
for e,s_,t,rn,src,sc,tc,extra,conf,ev in EDGES:
    a_,b_=N[s_],N[t]
    role = e=="IndicatesMalware"
    tbl = src.split(".")[1]
    cols = "$from_id, $to_id, " + ("Role, " if role else "") + "Confidence, EvidenceID"
    vals = "a.$node_id, b.$node_id, " + ("i.Role, " if role else "") + conf.replace("x.","i.") + ", " + ev.replace("x.","i.")
    cond = extra.replace(" AND x.", " AND i.") 
    dcond = extra.replace(" AND x.", " AND d.")
    name = f"trg_{tbl}_GraphEdge" if tbl!="Campaign" else "trg_Campaign_GraphAttribution"
    upd = f"\n    IF EXISTS (SELECT 1 FROM inserted) AND EXISTS (SELECT 1 FROM deleted) AND NOT (UPDATE(ActorID) OR UPDATE(AttributionEvidenceID)) RETURN;" if tbl=="Campaign" else ""
    w(f"CREATE OR ALTER TRIGGER dbo.{name} ON {src} AFTER INSERT, UPDATE, DELETE\nAS\nBEGIN\n    SET NOCOUNT ON;{upd}\n"
      f"    DELETE e\n    FROM dbo.{e} AS e\n    JOIN dbo.{a_[0]} AS a ON a.$node_id = e.$from_id\n    JOIN dbo.{b_[0]} AS b ON b.$node_id = e.$to_id\n"
      f"    JOIN deleted AS d ON d.{sc} = a.{a_[1]} AND d.{tc} = b.{b_[1]}{dcond};\n\n"
      f"    INSERT INTO dbo.{e} ({cols})\n    SELECT {vals}\n    FROM inserted AS i\n"
      f"    JOIN dbo.{a_[0]} AS a ON a.{a_[1]} = i.{sc}\n    JOIN dbo.{b_[0]} AS b ON b.{b_[1]} = i.{tc}\n    WHERE 1 = 1{cond};\nEND;\nGO\n")

open("/home/claude/tip/database/graph/05_graph.sql","w",encoding="utf-8").write("".join(o))

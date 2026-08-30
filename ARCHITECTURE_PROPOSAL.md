# Návrh interní aplikace pro evidenci tabulí a odřezků (laser / waterjet)

## 1) Hlavní architektonické rozhodnutí (jedna cesta)

**Doporučený stack:**
- **Frontend:** React + TypeScript + Konva (react-konva) + Zustand + TanStack Query
- **Backend:** NestJS (Node.js, TypeScript) + modulární monolit
- **Databáze:** PostgreSQL + PostGIS

**Proč tento stack:**
1. **PostGIS** řeší kritickou část (polygonové operace) robustněji než čisté JS knihovny v backendu.
2. **React + Konva** umožní rychle postavit praktický 2D editor (body, drag, zoom, pan) bez CAD složitosti.
3. **NestJS** dá stabilní strukturu, auditovatelnost a čisté API pro provoz ve výrobě.
4. **TypeScript end-to-end** sníží chyby v geometrii, jednotkách i API kontraktech.

---

## 2) Doménový model (co přesně evidovat)

### Entity
- `material_type` – ocel/nerez/hliník/plast
- `material_grade` – jakost (např. S235, 1.4301)
- `sheet_stock` – konkrétní tabule nebo odřezek
- `cut_job` – operace řezání (kdo, kdy, z čeho)
- `cut_shape` – polygon(y), které byly vyřezány
- `stock_movement` – audit pohybů na skladě

### Klíčové rozhodnutí
Každý fyzický kus materiálu (celá tabule i odřezek) je **jeden záznam v `sheet_stock`** se stavem:
- `FULL_SHEET`
- `REMNANT`
- `CONSUMED`

Tím pádem je sklad i historie jednoduchá: nic nemažeme, jen měníme stav a přidáváme nové kusy.

---

## 3) Databáze a geometrie (kritická část)

## 3.1 Uložení geometrie
Použít PostGIS sloupec:
- `shape geometry(MultiPolygon, 3857)`

Poznámka k jednotkám: v aplikaci držet **mm**, v geometrii ukládat převedené hodnoty (např. 1 jednotka = 1 mm), konzistentně v celé aplikaci.

## 3.2 Výkonové sloupce
Do `sheet_stock` přidat:
- `bbox geometry(Polygon, 3857)` – obálka pro rychlé filtrování
- `area_mm2 numeric(14,2)` – rychlé řazení a reporting

A indexy:
- `GIST(shape)`
- `GIST(bbox)`
- B-tree na (`material_type`, `thickness_mm`, `status`)

## 3.3 Historie změn
- `stock_movement` jako append-only tabulka.
- U každé operace ukládat:
  - `operation_type` (`CUT`, `MERGE`, `ADJUSTMENT`)
  - `source_stock_id`
  - `result_stock_ids[]`
  - `operator_id`
  - `created_at`
  - `payload_json` (metadata, důvod korekce, importovaný soubor)

To je auditně bezpečné a vhodné pro výrobu.

---

## 4) Konkrétní geometrické operace

## 4.1 Difference / Intersection
Primární výpočet vždy v DB přes PostGIS:
- `ST_Difference(source.shape, cut_union)`
- `ST_Intersection(source.shape, query_shape)`
- `ST_Union` pro sloučení více vyřezaných polygonů do jedné operace

## 4.2 Validace polygonů
Před výpočtem:
1. `ST_IsValid(shape)`
2. pokud nevalidní: `ST_MakeValid(shape)`
3. zahození mikrozbytků pod prahem (např. `< 500 mm²`): `ST_Area`
4. kontrola, že řez je uvnitř zdrojové tabule: `ST_CoveredBy(cut, source)`

## 4.3 Výkon
- Dávkové operace řešit v jedné SQL transakci.
- Pro editor držet simplifikovanou geometrii pro náhled (`ST_SimplifyPreserveTopology`), ale ukládat plnou.
- Pro vyhledání vhodného odřezku používat bbox + area prefilter, teprve pak přesná intersection kontrola.

---

## 5) 2D editor – praktický návrh UX

### Co operátor musí umět (MVP verze)
1. Otevřít tabuli/odřezek.
2. Klikáním kreslit polygon řezu.
3. Uzavřít polygon (klik na první bod / Enter).
4. Táhnout body (drag&drop).
5. Zoom kolečkem, pan prostředním tlačítkem.
6. Vidět rozměry (šířka/výška bbox + plocha).

### Implementace ve frontendu
- `react-konva` canvas vrstva pro geometrii.
- Snap na mřížku 1 mm nebo 5 mm (přepínatelné).
- Undo/redo lokálně (stack posledních 20 akcí).
- Odeslat polygon jako GeoJSON.

### Server flow po kliknutí „Uložit řez“
1. Backend validuje polygon.
2. V jedné transakci spočte `difference`.
3. Zdrojový kus přepne na `CONSUMED` nebo sníží podle výsledku.
4. Vytvoří nové `sheet_stock` záznamy pro zbytky (`REMNANT`).
5. Zapíše `stock_movement`.

---

## 6) Reálný výrobní workflow (jednoduchý pro obsluhu)

1. Operátor načte zakázku.
2. Systém nabídne vhodné kusy: nejdřív odřezky, pak celé tabule.
3. Operátor zvolí kus (materiál + tloušťka + minimální rozměr).
4. Nakreslí řez (nebo importuje DXF polygon).
5. Potvrdí řez.
6. Sklad se aktualizuje automaticky.
7. Na skladě se objeví nové využitelné odřezky s náhledem tvaru.

Klíčové: obsluha neřeší geometrii ručně, jen potvrdí výsledek.

---

## 7) MVP plán (rychlé nasazení)

## Fáze 1 – 4 až 6 týdnů
Implementovat:
- Evidence celých tabulí a odřezků
- 2D editor s polygonem + editace bodů + zoom/pan
- `difference` v PostGIS
- Automatické založení nových odřezků
- Základní audit (`stock_movement`)
- Jednoduché role: operátor, mistr

Odložit:
- pokročilý nesting
- kolizní plánování strojů
- ERP/MES integrace
- realtime spolupráce více uživatelů

## Fáze 2
- Import DXF (uzavřené kontury)
- Poloautomatický výběr nejlepšího odřezku
- Tisk štítků s QR pro odřezky

## Fáze 3
- Pokročilé nesting optimalizace
- Predikce spotřeby materiálu

---

## 8) API návrh (konkrétní)

- `POST /api/stock/sheets` – založení tabule
- `GET /api/stock/search?material=steel&thickness=4&minW=800&minH=600`
- `GET /api/stock/:id/shape` – polygon kusu
- `POST /api/cuts` – provedení řezu nad jedním kusem
- `GET /api/movements?from=...&to=...` – audit

### `POST /api/cuts` request
```json
{
  "sourceStockId": "f01d...",
  "cutPolygons": [{ "type": "Polygon", "coordinates": [[[0,0],[100,0],[100,50],[0,0]]] }],
  "machine": "LASER_TRUMPF_3030",
  "operatorId": "u-123"
}
```

### response
```json
{
  "consumedStockId": "f01d...",
  "createdRemnants": ["r-001", "r-002"],
  "discardedMicroRemnants": 1,
  "movementId": "m-777"
}
```

---

## 9) Ukázka implementace (NestJS + PostGIS)

```ts
// cut.service.ts
async performCut(cmd: PerformCutCommand): Promise<CutResultDto> {
  return this.db.tx(async (trx) => {
    const source = await trx.one(`
      SELECT id, shape
      FROM sheet_stock
      WHERE id = $1
      FOR UPDATE
    `, [cmd.sourceStockId]);

    // 1) GeoJSON -> geometry
    await trx.none(`CREATE TEMP TABLE tmp_cuts (geom geometry(MultiPolygon, 3857)) ON COMMIT DROP;`);

    for (const poly of cmd.cutPolygons) {
      await trx.none(`
        INSERT INTO tmp_cuts(geom)
        VALUES (ST_Multi(ST_SetSRID(ST_GeomFromGeoJSON($1), 3857)))
      `, [JSON.stringify(poly)]);
    }

    // 2) validace a union řezu
    const cut = await trx.one(`
      SELECT ST_UnaryUnion(ST_Collect(ST_MakeValid(geom))) AS geom
      FROM tmp_cuts
    `);

    // 3) kontrola, že řez leží uvnitř zdroje
    const covered = await trx.one(`
      SELECT ST_CoveredBy($1::geometry, $2::geometry) AS ok
    `, [cut.geom, source.shape]);

    if (!covered.ok) throw new Error('Cut polygon is outside source sheet');

    // 4) difference -> nové odřezky
    const remnants = await trx.manyOrNone(`
      WITH diff AS (
        SELECT ST_CollectionExtract(ST_MakeValid(ST_Difference($1::geometry, $2::geometry)), 3) AS g
      ),
      parts AS (
        SELECT (ST_Dump(g)).geom AS geom FROM diff
      )
      SELECT geom, ST_Area(geom) AS area
      FROM parts
      WHERE ST_Area(geom) >= 500
    `, [source.shape, cut.geom]);

    // 5) změna skladu + audit (zkráceno)
    // ... insert remnants, mark source consumed, insert stock_movement

    return {
      consumedStockId: cmd.sourceStockId,
      createdRemnants: remnants.length,
    };
  });
}
```

---

## 10) Jedno hlavní doporučení na závěr

Začněte **co nejdřív s PostGIS-first geometrií** a jednoduchým editorem. 
Nejčastější selhání podobných projektů je, že tým začne optimalizacemi (nesting, AI), ale nemá spolehlivý základ sklad + validní geometrii + audit.

Tady je priorita správně opačně: 
1) přesná evidence,
2) robustní polygon operace,
3) teprve potom optimalizace.

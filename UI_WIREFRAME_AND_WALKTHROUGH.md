# Jak to bude fungovat v praxi + návrh obrazovek (iterativní verze)

Tento návrh je připravený tak, abychom ho mohli ladit „za pochodu“: po každé části mi řeknete co sedí a co upravit.

---

## 1) Jak to funguje (end-to-end, jednoduše)

## Krok 1: Operátor otevře „Nový řez“
- Vybere:
  - materiál (např. nerez)
  - tloušťku (např. 4 mm)
  - stroj (laser/waterjet)
- Systém nabídne vhodné kusy:
  - nejdřív odřezky
  - potom celé tabule

## Krok 2: Výběr kusu
- Operátor klikne na kartu kusu (náhled tvaru + rozměr + plocha + pozice ve skladu).
- Klikne **Použít kus**.

## Krok 3: Editor řezu
- Vlevo seznam zakázkových dílů nebo ruční kreslení.
- Uprostřed 2D plocha se zvoleným kusem.
- Operátor kliká body polygonu (co se vyřízlo), body může táhnout.
- Vidí rozměry a plochu výřezu.

## Krok 4: Potvrdit řez
- Klik na **Spočítat zbytek**.
- Backend provede `difference` a vrátí nové odřezky.
- Operátor vidí náhled „před/po“ a potvrdí **Uložit do skladu**.

## Krok 5: Sklad se aktualizuje
- Původní kus se označí jako spotřebovaný nebo upravený.
- Vzniknou nové odřezky se štítkem, plochou, náhledem.
- Do historie se zapíše kdo/co/kdy.

---

## 2) Návrh obrazovek (wireframe)

## Obrazovka A: Výběr kusu materiálu

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Nový řez                                                            │
├─────────────────────────────────────────────────────────────────────┤
│ Materiál: [Nerez ▼]  Tloušťka: [4 mm ▼]  Stroj: [Laser 3030 ▼]     │
│ Min. rozměr dílu: [800] x [600] mm                                 │
│ [Najít vhodné kusy]                                                 │
├─────────────────────────────────────────────────────────────────────┤
│ Doporučené odřezky                                                  │
│ ┌───────────────┐  ┌───────────────┐  ┌───────────────┐             │
│ │ Náhled tvaru  │  │ Náhled tvaru  │  │ Náhled tvaru  │             │
│ │ ID: R-1021    │  │ ID: R-0988    │  │ ID: R-1102    │             │
│ │ 920x740 mm    │  │ 870x690 mm    │  │ 1200x650 mm   │             │
│ │ 0.58 m²       │  │ 0.49 m²       │  │ 0.62 m²       │             │
│ │ [Použít kus]  │  │ [Použít kus]  │  │ [Použít kus]  │             │
│ └───────────────┘  └───────────────┘  └───────────────┘             │
└─────────────────────────────────────────────────────────────────────┘
```

## Obrazovka B: Editor řezu

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Zakázka: ZK-2026-0417     Kus: R-1021 (nerez 4 mm)                          │
├───────────────────────┬──────────────────────────────────────────────────────┤
│ Nástroje              │                    2D editor                        │
│ ─ Polygon řezu        │  ┌──────────────────────────────────────────────┐    │
│ ─ Posun (Pan)         │  │                                              │    │
│ ─ Zoom + / -          │  │         [obrys odřezku]                      │    │
│ ─ Snap: 1 mm          │  │            ●─────●                            │    │
│ ─ Undo / Redo         │  │           /       \                           │    │
│                       │  │          ●   výřez  ●                          │    │
│ Rozměry výřezu        │  │           \       /                           │    │
│ W: 312.4 mm           │  │            ●─────●                            │    │
│ H: 188.7 mm           │  │                                              │    │
│ Plocha: 0.043 m²      │  └──────────────────────────────────────────────┘    │
│                       │                                                      │
│ [Spočítat zbytek]     │ [Náhled před/po] [Uložit do skladu]                 │
└───────────────────────┴──────────────────────────────────────────────────────┘
```

## Obrazovka C: Potvrzení a výsledek

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Výsledek řezu                                                       │
├─────────────────────────────────────────────────────────────────────┤
│ Spotřebovaný kus: R-1021                                            │
│ Vzniklé odřezky: 2                                                   │
│  - R-1207 | 610x420 mm | 0.21 m²                                    │
│  - R-1208 | 280x190 mm | 0.05 m²                                    │
│ Mikrozbytky pod 500 mm²: 1 (neuloženo)                              │
│                                                                     │
│ [Potvrdit a uložit]   [Zpět do editoru]                             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3) Co implementovat hned, aby to šlo používat

## Sprint 1 (nejdůležitější)
- Výběr kusu + filtr materiál/tloušťka
- Jednoduchý editor polygonu (klikání bodů, drag bodů, zoom/pan)
- Tlačítko „Spočítat zbytek“
- Uložení výsledných odřezků do skladu

## Sprint 2
- Import DXF kontury
- Poloautomatický výběr nejlepšího kusu
- Tisk štítku (QR + ID odřezku)

---

## 4) Jak budeme ladit „za pochodu“ (váš požadovaný režim)

Navrhuju postup po malých krocích:
1. **Vy potvrdíte obrazovku A** (výběr kusu) – co přidat/ubrat.
2. Pak doladíme **obrazovku B** (editor), zejména ovládání pro operátora.
3. Pak **obrazovku C** (potvrzení a audit).
4. Teprve potom začneme „ostré“ UI komponenty.

Aby to bylo rychlé, stačí mi od vás vždy krátká zpětná vazba ve formátu:
- ✅ Co je dobře
- 🔧 Co změnit
- ❌ Co odstranit

---

## 5) První konkrétní doporučení pro vás teď

Začněme potvrzením těchto 3 bodů:
1. Má být výchozí priorita opravdu „nejdřív odřezky, až pak celé tabule“?
2. Má operátor kreslit jen **jeden polygon na jeden řez**, nebo více najednou?
3. Je pro vás minimum ukládat odřezek až od **500 mm²**, nebo chcete jiný práh?

Jakmile tohle upřesníte, připravím přesný návrh komponent (fields, tlačítka, validace, chybové hlášky) pro implementaci 1:1.

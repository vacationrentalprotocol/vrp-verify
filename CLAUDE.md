# CLAUDE.md — vrp-verify

## Källan först — inga gissningar (VD 2026-11-03)

VRP är en global öppen standard. Ett felaktigt påstående kan skada den.

1. **Källan först.** Säg innan du svarar vilken primärkälla som avgör frågan, och läs den. Det snabbaste verktyget är inte källan.
2. **Varje påstående är märkt:** `mätt` (URL eller verktyg + UTC), `läst` (fil:rad@SHA, eller dokument + avsnitt) eller `inte kontrollerat`. Ett påstående utan märkning får inte stå.
3. **Ett verktygs sammanfattning är aldrig bevis.** Sökverktyg, AI-sammanfattningar och andra AI:s svar är ledtrådar. Bara rådata från källan räknas.
4. **En källa är en källa.** Dra aldrig slutsatser från ett verktyg om «webben», «alla», «aldrig» eller «ingen».
5. **Rekommendation först efter mätning.** Ingen slutsats och ingen rekommendation får bygga på något som är `inte kontrollerat`.
6. **Gamla anteckningar mäts om.** LAGE, ADR:er, minnen och sammanfattningar säger vad som gällde då. Mät igen innan något upprepas som läget nu.
7. **Fel rättas direkt och öppet:** vad som var fel, vilken källa som visar det rätta, och vilka andra påståenden som byggde på felet.
8. **Granskaren avvisar** varje påstående utan märkning, oavsett vilken AI som skrev det.

### Källkartan

| Frågan | Primärkällan |
|---|---|
| Är det live? | Produktionens URL: svaret läst, med UTC-tid |
| Vad står i koden eller specen? | Repot vid origin/main-SHA, fil:rad |
| Hämtar sökmotorer och AI-robotar sidorna? | Vercel Observability: `vercel.request.count` per `bot_name` och `request_hostname` |
| Är sidan indexerad, och för vilka sökord? | Google Search Console och Bing Webmaster Tools (ägarens data) |
| Kommer besökare från sökning eller AI? | Vercel Web Analytics per `referrerHostname` |
| Version och ägare på npm | registry.npmjs.org |
| PR, ärenden, granskningar, säkerhetsrapporter | GitHubs API |
| Vad kräver IETF, W3C, OpenID och andra standardorgan? | Originaldokumentet: ordagrant citat och avsnitt |
| Bokningar, betalningar och data | Supabase och Stripe: raden läst, med UTC-tid |

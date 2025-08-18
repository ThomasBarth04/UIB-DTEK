# Rapport – innlevering 1
**Team: Death Crushers 1000**

**medlemmer**:<br/> *Jesper Hammer<br/>
Zeno Elio Leonardi<br/>
Thomas Barth<br/>
Izaak Sarnecki<br/>
Johanne Blikberg Herheim.<br/>* 

## Konseptbeskrivelse 

### Spillbeskrivelse
Vårt spill er en roguelike kortbasert strategi-opplevelse inspirert av Slay the Spire. Spilleren velger en karakter og navigerer gjennom en serie av kamper, hendelser og butikker, hvor målet er å bygge en sterk kortstokk og beseire fiender og bosser. 

Viktige aspekter i spillet:
1. Spillfigur og interaksjoner 
  - Karakteren deltar i turbaserte kortkamper mot fiender.
  - Spilleren kan administrere kortstokken ved å legge til, fjerne og oppgradere kort.

2. Spillverden og progresjon
  - Verden er strukturert som et tre med grener, der spilleren velger ruter mellom kamper, butikker, skattekister og tilfeldige hendelser. 
  - Kartet og innhldet genereres proseduralt for å gi variasjon.

3. Kortmekanikk
  - Spilleren starter med en grunnlegende kortstokk og bygger den opp ved å legge til nye kort etter kamper. 
  - Kort spilles ved å bruke en begrenset mengde energi per tur.
  - Det finnes ulike korttyper:
    - Angrepskort: Gjør skade på fiende
    - Forsvarskort: Gir spilleren blokkering for å redusere skade
    - Ferdighetskort: Gir spesielle effekter som korttrekking, energi eller statusendringer
    - Kraftkort: Gir varige fordeler i kampen.
  - Kort kan oppgraderes for å forbedrede effekter.

4. Fiender og bosser:
  - Fiender har egne kortmekanikker og angrepsmønstre som kan forutses gjennom indikasjoner
  - Noen fiender legge statuser i spillerens kortstokk som skaper utfordringer
  - Bossene er kraftigere fiender med unike evner og spesialangrep

5. Ressurser:
  - Penger brukes til å kjøpe kort i butikker
  - Helse (HP) er begrenset og kan kun gjenopprettes på bestemte steder.

6. Død og progresjon:
- Spillet har en "permadeath"-mekanikk hvor død betyr at man må starte på nytt
- Etter hvert gjennomført løp kan nye kort låses opp for fremtidige gjennomspillinger

7. Brukergrensesnitt og stil:
- Spillet vil ha en stilisert tegneserieaktig estetikk med tydelige ikoner og kortillustrasjoner
- En intuitiv meny for kortstokkadministrasjon og karakterprogresjon
- Animert kortspilling for å gi en visuell respons til spillerens valg. 

## Utviklingsprosess

Vi bruker en slags Scrum tilnærming og seter "milestones" som vi jobber mot. De består av ulike todos som utgjør en større feature eller MVP.

Flyten ser slik ut:

1. Finn en task på Trello
2. Finn ut av hva som må til for å lage den tingen. Spør gjerne andre medlemmer om de har peiling på det eller noe input.
3. Lag tingen. Lag også gjerne tester.
4. Lag merge request. Med mindre det er en veldig liten ting burde minst én person reviewe MRen.
5. Merge inn i main
6. Legg til litt dokumentasjon i Wikien om det er en større feature. Beksriv hvordan man bruker det, ikke hvordan det funker, og gi eksempler.
7. Oppdater Trello. Fant du noen nye ting vi mangler? Er det noe som blokker og gjør at du ikke kan fullføre? Mangler featuren noe som bør legges til senere? Osv osv

## MVP

* Main Menu (med knapp for start)
* Viser kart med ulike noder (trykke node for å starte level)
* Man har kort, en bunke, og discard, (uendelig strøm i debug) og brukte kort går i discard. På starten av ny tur blir man tildelt nye kort.
* Når banen er ferdig vises et victory screen og man går tilbake til map og gjentar prosessen.
* Når alle baner er ferdig får man game complete screen og er ferdig med spillet (sendt tilbake til main menu)

## Retroperspektiv

Funker bra å møtes i gruppetimer. Har en konkret plan for spillet. Har fordelt roller og ansvar. Tidsestimat har vært bra :)

## Roller

- Scrum Master (Jesper): "Team lead", passe på at alle har oppgaver, organisere prosjekt
- Design Guru (Zeno): Design og grafikk, lage konsept for spillet, lage maler og regler for utvikling av assets
- Tech Support (Izaak): Rask bug fixer, ansvar for å raskt fikse små og kritiske feil ASAP.
- DJ (Thomas): Lyd og musikk, ansvar for lyd-effekter og musikk, tema, og verktøy
- Teste Dronning (Johanne): Passe på at tester er på plass, sørge for at folk tester nye features, legge til edge case tester


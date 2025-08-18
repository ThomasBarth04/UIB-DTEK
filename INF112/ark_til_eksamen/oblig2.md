# Rapport – innlevering 1
**Team: Death Crushers 1000**

**medlemmer**:
* Jesper Hammer
* Zeno Elio Leonardi
* Thomas Barth
* Izaak Sarnecki
* Johanne Blikberg Herheim


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

1. Finn en task på [Trello](https://trello.com/b/ZCyL9prn/death-crushers-1000)
2. Finn ut av hva som må til for å lage den tingen. Spør gjerne andre medlemmer om de har peiling på det eller noe input.
3. Lag tingen. Lag også gjerne tester.
4. Lag merge request. Med mindre det er en veldig liten ting burde minst én person reviewe MRen.
5. Merge inn i main
6. Legg til litt dokumentasjon i Wikien om det er en større feature. Beksriv hvordan man bruker det, ikke hvordan det funker, og gi eksempler.
7. Oppdater Trello. Fant du noen nye ting vi mangler? Er det noe som blokker og gjør at du ikke kan fullføre? Mangler featuren noe som bør legges til senere? Osv osv


## MVP
1. Start menu
   * New game
   * Settings
     * Skru av og på musikk og sfx
     * Endre må musikk og sfx volum
   * Quit
2. Musikk som spiller
3. Vise kart med noder som starter en fight
   * Kunne flytte rundt på kartet
4. Vise kort når man starter spill
   * Trekke kort
   * Avslutte tur
   * Spille kort
     * Angripe fienden
     * Forsvare seg mot fienden
     * Stunne fienden
5. Dø når man går tom for liv
   * Starte nytt spill
6. Vinne når motstander ikke har mer liv
   * Går tilbake til kartet og man kan velge ny fight.

## Brukerhistorier
1. SplashScreen
   * Som spiller vil jeg se en splashscreen når jeg starter spillet som vises i noen sekunder. Her står gruppenavn, spillnavn og framework (libGDX).
2. Startmeny
   * Som spiller vil jeg kunne starte et nytt spill for å komme i gang.
   * Som spiller vil jeg gå inn i innstillinger og skru av og på musikk og sfx.
   * Som spiller vil jeg kunne avslutte spillet.
3. Kart
   * Som spiller vil jeg kunne se et kart med noder som representerer kamper. Ikke alle kamper er tilgjengelige med en gang.
   * Som spiller vil jeg kunne flytte rundt på kartet.
4. Kamp
   * Som spiller vil jeg kunne se kortene mine og trekke nye kort.
   * Som spiller vil jeg kunne spille kortene mine og angripe, stunne og forsvare meg mot fienden.
   * Som spiller vil jeg kunne se min og fiendens kort og helse.
5. Død
   * Som spiller vil jeg dø når jeg går tom for liv og starte et nytt spill. Da vises en defeat-skjerm og kan jeg starte et nytt spill om jeg vil.
6. Seier
   * Som spiller vil jeg vinne når motstanderen ikke har mer liv. Da vises en victory-skjerm og jeg kan velge en ny fight.



## Retrospekt
Rollene i teamet har fungert bra og vi har ikke behov for nye roller. Vår team lead passer på at alle har oppgaver og fordeler nye oppgaver til de som ikke har. Design guru bruker tid på både å tegne grafikken som skal brukes og legger til funksjoner til spillet. Tech supporten hjelper med bugs og gjør mye code review. DJ har implementert audio manageren vi bruker og utviklet nyttige utils. Test dronningen passer på at vi skriver tester og at testprosenten går oppover. Teamet er fornøyd med prosjektmetodadikk og valg vi har tatt. Gruppedynamikken er velfungerende og alle kommer med sine meninger, bidrar godt til prosjektet og er lett å få kontakt med.
Vi er ganske fornøyde med det vi har fått til så langt. Spillet har kommet seg til MVP og dette er vi fornøyd med. Når det kommer til forbedringspotensiale kunne vi gjort noen avgjørelser angående desing og spillnavn, og å huske å oppdatere trello og lage tester. Det er fort å glemme.

**Klassediagram**
![Klassediagram](doc/class-diagram.png)

## Dette har vi fikset siden sist
* Oppdatert MVP
* Oppnådd MVP
* Fått opp testprosenten
* Brukerhistorier
* Klassediagram

## Roller

- Scrum Master (Jesper): "Team lead", passe på at alle har oppgaver, organisere prosjekt
- Design Guru (Zeno): Design og grafikk, lage konsept for spillet, lage maler og regler for utvikling av assets
- Tech Support (Izaak): Rask bug fixer, ansvar for å raskt fikse små og kritiske feil ASAP.
- DJ (Thomas): Lyd og musikk, ansvar for lyd-effekter og musikk, tema, og verktøy
- Teste Dronning (Johanne): Passe på at tester er på plass, sørge for at folk tester nye features, legge til edge case tester

## Møtereferater
Møtereferatene vi har ligger i denne google doc-en.
### [Google doc](https://docs.google.com/document/d/1WfEtzExT4xF1IWqi6dMqeTZf7Evc8MFy4sm8Yu5cxas/edit?usp=sharing)
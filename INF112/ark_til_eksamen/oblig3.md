# Rapport – innlevering 3

**Team: Death Crushers 1000**

**medlemmer**:

- Jesper Hammer
- Zeno Elio Leonardi
- Thomas Barth
- Izaak Sarnecki
- Johanne Blikberg Herheim

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
   - New game
   - Settings
     - Skru av og på musikk og sfx
     - Endre må musikk og sfx volum
   - Quit
2. Musikk som spiller
3. Vise kart med noder som starter en fight
   - Kunne flytte rundt på kartet
4. Vise kort når man starter spill
   - Trekke kort
   - Avslutte tur
   - Spille kort
     - Angripe fienden
     - Forsvare seg mot fienden
     - Stunne fienden
5. Dø når man går tom for liv
   - Starte nytt spill
6. Vinne når motstander ikke har mer liv
   - Går tilbake til kartet og man kan velge ny fight.

## Brukerhistorier

### 1. SplashScreen

- **Som spiller vil jeg se en splashscreen når jeg starter spillet som vises i noen sekunder.**  
  Her står gruppenavn, spillnavn og framework (libGDX),  
  **fordi jeg ønsker en profesjonell introduksjon som viser hvem som har laget spillet og hvilken teknologi som brukes.**
  - **Akseptanskriterie:**  
    Når spillet åpnes skal man umiddelbart se splash screen med gitt info.

### 2. Startmeny

- **Som spiller vil jeg kunne starte et nytt spill for å komme i gang,**  
  fordi jeg vil begynne å spille uten unødvendige steg.
- **Som spiller vil jeg gå inn i innstillinger og skru av og på musikk og sfx,**  
  fordi jeg ønsker å tilpasse lydnivået etter eget ønske eller situasjon.
- **Som spiller vil jeg kunne avslutte spillet,**  
  fordi jeg trenger en enkel måte å avslutte når jeg er ferdig med å spille.
  - **Akseptanskriterie:**  
    Etter splash screen vises det en meny med fungerende knapper som sender til riktig state.

### 3. Kart

- **Som spiller vil jeg kunne se et kart med noder som representerer kamper. Ikke alle kamper er tilgjengelige med en gang,**  
  fordi jeg ønsker å forstå progresjonen og få en følelse av fremgang i spillet.
- **Som spiller vil jeg kunne flytte rundt på kartet,**  
  fordi jeg vil kunne utforske tilgjengelige ruter og finne neste utfordring selv.
  - **Akseptansekriterie:**  
    Når kartet vises skal det inneholde flere noder, hvor kun noen er tilgjengelige fra starten.  
    Spiller skal kunne navigere rundt på kartet ved hjelp av tastatur eller mus/berøring.  
    Klikk på en tilgjengelig node skal starte en kamp.

### 4. Kamp

- **Som spiller vil jeg kunne se kortene mine og trekke nye kort,**  
  fordi jeg trenger oversikt over handlingsmulighetene mine i kamp.
- **Som spiller vil jeg kunne spille kortene mine og angripe, stunne og forsvare meg mot fienden,**  
  fordi jeg vil påvirke utfallet av kampen gjennom strategiske valg.
- **Som spiller vil jeg kunne se min og fiendens kort og helse,**  
  fordi jeg trenger informasjon for å ta riktige avgjørelser.
  - **Akseptansekriterie:**  
    Spillerens kort vises i hånden ved kampstart, og nye kort kan trekkes hver runde.  
    Kort kan dras eller aktiveres for å utføre handlinger som angrep, forsvar og stun.  
    Helseverdier for både spiller og fiende er synlige og oppdateres ved skade eller heling.  
    Fienden skal også utføre handlinger basert på enkel AI.

### 5. Død

- **Som spiller vil jeg dø når jeg går tom for liv og starte et nytt spill. Da vises en defeat-skjerm og kan jeg starte et nytt spill om jeg vil,**  
  fordi jeg vil ha en tydelig konsekvens for å tape, men også en enkel måte å prøve på nytt.
  - **Akseptansekriterie:**  
    Når spillerens helse når null, skal det vises en "Defeat"-skjerm.  
    "Defeat"-skjermen skal ha en knapp for å starte et nytt spill.  
    Kart og tidligere progresjon skal nullstilles ved nytt spill.

### 6. Seier

- **Som spiller vil jeg vinne når motstanderen ikke har mer liv. Da vises en victory-skjerm og jeg kan velge en ny fight,**  
  fordi jeg vil ha en følelse av mestring og progresjon etter seier.
  - **Akseptansekriterie:**  
    Når fiendens helse når null, skal det vises en "Victory"-skjerm.  
    "Victory"-skjermen skal ha en knapp for å returnere til kartet og velge en ny tilgjengelig kamp.  
    Den bekjempede noden skal vises som fullført eller låst.

## Retrospekt

### Hva fungerer bra

Rollene i teamet har fungert godt, og det er ikke identifisert behov for nye roller.

- **Team lead** fordeler arbeidsoppgaver effektivt og sørger for at ingen står uten noe å gjøre.
- **Design-guru** har fortsatt å bidra sterkt både med grafikk og funksjonalitet.
- **Tech support** tar ansvar for feilsøking og gjør grundig code review.
- **DJ** har implementert vår audio manager og flere nyttige utils.
- **Test-dronningen** holder fokus på testing og jobber aktivt med å øke testdekningen.

Teamet er fornøyd med prosjektmetodikken og valgene som er tatt. Gruppedynamikken er fortsatt sterk, med god kommunikasjon og jevn fordeling av innsats. Alle er involvert og bidrar aktivt med ideer og til gjennomføringen.

Vi har nådd **Minimum Viable Product (MVP)**, og dette er vi stolte av. Flere viktige funksjoner er på plass, og spillet føles nå mer helhetlig og komplett.

### Hva har vi gjort siden sist

- Refaktorert hele prosjektet til å bruke **MVC-arkitektur**, som har gitt bedre struktur og skille mellom logikk, visning og kontroll.
- Lagt til **sprites for bakgrunn** i kampsystemet og **kortillustrasjoner**, noe som har forbedret det visuelle inntrykket betydelig.
- Designet og implementert **flere nye kort**, som gir mer variasjon og dybde i gameplay.
- Implementert **flere fiender** med ulik oppførsel, som gir bedre kampdynamikk.
- Lagt til **sprites for kart-noder**, som tydeliggjør fremdrift og interaktivitet på kartet.
- Fullført en **mer komplett game loop** med overgang mellom kamp, seier/tap og videre progresjon.

### Forbedringspotensial

- Vi kunne vært tidligere ute med enkelte beslutninger rundt **design og navn på spillet**.
- **Trello** og oppdatering av oppgavekort blir fortsatt lett glemt i travle perioder.
- Det er også rom for forbedring når det gjelder **kontinuerlig testskriving**, slik at vi holder testdekningen stabil og høy.

### Veien videre

- Ferdigstille siste visuelle elementer og polering.
- Sørge for at testdekningen forblir høy ved å teste nye features fortløpende.
- Fortsette iterativ utvikling og bruk av MVC som fundament.
- Evaluere feedback og gjøre eventuelle justeringer før finalen.

## Klassediagram

![Klassediagram](doc/class-diagram.png)

## Dette har vi fikset siden sist

- Nye sprites for map, kort, og bakgrunner
- Refactor hele prosjektet til å bruke MVC
- Ny Shop state

## Roller

- Scrum Master (Jesper): "Team lead", passe på at alle har oppgaver, organisere prosjekt
- Design Guru (Zeno): Design og grafikk, lage konsept for spillet, lage maler og regler for utvikling av assets
- Tech Support (Izaak): Rask bug fixer, ansvar for å raskt fikse små og kritiske feil ASAP.
- DJ (Thomas): Lyd og musikk, ansvar for lyd-effekter og musikk, tema, og verktøy
- Teste Dronning (Johanne): Passe på at tester er på plass, sørge for at folk tester nye features, legge til edge case tester

## Møtereferater

Møtereferatene vi har ligger i denne google doc-en.

### [Google doc](https://docs.google.com/document/d/1WfEtzExT4xF1IWqi6dMqeTZf7Evc8MFy4sm8Yu5cxas/edit?usp=sharing)


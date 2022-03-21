# Virksomhetssertifikat-generator for testing 

Denne appen genererer virksomhetssertifkater i en egen jks. Disse sertifikatene inneholder en struktur som er delvis
lik den som kreves gjennom virksomhetssertifkater i det offentlige. Det vil si at alle sertifikater blir generert med
root og mellomliggende sertifikater. Det betyr også at subjectfelt, extensions, policy, distributionpoints osv er satt
opp i henhold til standarden.

NB: Disse virksomhetssertifkatene kan bare brukes i intern testing. For et reelt test eller/og produksjons-virksomhetsertifkat måtte dette kjøpes av en CA som utsteder virksomhetssertifkater.

## Forutsetninger

- Java 1.8
- Maven 3.3
- Endre organisasjonsnummer til din virksomhetsorgnr i TestVirksomhetGenerator.java
- TestVirksomhetGenerator.CRL_PATH må endres til annen url. Denne er bare tilgjengelig for internt hos Difi. 

## Bruk

Man bygger prosjektet

    mvn assembly:assembly

Så kan man generere sertifikater ved å kjøre

    java -jar target/certificate-generator-DEV-SNAPSHOT-jar-with-dependencies.jar

Hvis man ønsker å generere sertifikater utfra en tidligere root og eller mellomligende så kan man spesifisere JKS for
dette.

    java -jar target/certificate-generator-DEV-SNAPSHOT-jar-with-dependencies.jar min-virksomhet-testsertifikater.jks changeit

Dette krever at JKS-en inneholder root og intermediate som alias på riktige nøkler og at passordet er likt for begge.

## Nøkler

Nøklene med orgnummer er korrekte og vil validere i Oppslagstjenesten for kontakt og reservasjonsregisteret (Gitt at orgnumemr er godkjent). Andre alias
beskriver en tenkt feilsituasjon der nøklene ikke vil validere i Oppslagstjensten og man vil få en fornuftig
feilmelding.
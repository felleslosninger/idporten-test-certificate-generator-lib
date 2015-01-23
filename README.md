

#Virksomhetssertifkat generator


Denne appen genererer virksomhetssertifkater i en egen jks. Disse sertifikatene inneholder en struktur som er delvis
lik den som kreves gjennom virksomhetssertifkater i det offentlige. Det vil si at alle sertifikater blir generert med
root og mellomliggende sertifikater. Det betyr også at subjectfelt, extensions, policy, distributionpoints osv er satt
opp i henhold til standarden.

##Bruk


Man bygger prosjektet

    mvn assembly:assembly

Så kan man generere sertifikater ved å kjøre

    java -jar target/certificate-generator-1.0-SNAPSHOT-jar-with-dependencies.jar

Hvis man ønsker å generere sertifikater utfra en tidligere root og eller mellomligende så kan man spesifisere jks for
dette.

    java -jar target/certificate-generator-1.0-SNAPSHOT-jar-with-dependencies.jar difi-virksomhet-testsertifikater.jks changeit

Dette krever at jksen inneholder root og intermediate som alias på riktige nøkkler og at passordet er likt for begge.

##Nøkkler


Nøkklene med orgnummer er korrekte og vil validere i oppslagstjenesten. (Gitt at orgnumemr er godkjent) Andre alias
beskriver en tenkt feilsituasjon. Disse nøkklene vil ikke validere i oppslagstjensten og man skal få en fornuftig
feilmelding.
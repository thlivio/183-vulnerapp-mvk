# Vulnerapp

-- A Vulnerable Sample Spring Boot Application

This application uses a relatively modern stack but is still vulnerable to a set of attacks.
Featuring:

- [XSS](https://portswigger.net/web-security/cross-site-scripting)
- [SQLi](https://portswigger.net/web-security/sql-injection)
- [CSRF](https://portswigger.net/web-security/csrf)
- [SSRF](https://portswigger.net/web-security/ssrf)
- Fake Logins
- Info Exposure
- Plain Passwords
- ...

Either start it via IDE or start it with the following command (it will hang). Then visit http://localhost:8080/

```console
./gradlew bootRun
```


# Diskussion und Selbstevaluation
## 1. Implementierte Sicherheitsmassnahmen:
Role based Access Control: Wurde bei den jeweiligen Controllern (zb. Admin controller) und bei securitConfiguration hinzugefügt (mit .hasRole("ADMIN")).
Die default Rolle ist USER, siehe UserEntity.


session based Authentifizierungslösung: 
wurde mit CSRF token umgesetzt, siehe SecurityConfig und CsrfController.
ist wichtig, da so username und password nicht bei jedem request mitgesendet werden müssen, sondern nur einmalig beim login.
schützt vor cross site scripting, da der browser das token nicht mit sendet, wenn die Anfrage von einer anderen Seite kommt.

Passwort-speicherung: 
passwort wird nur gehasht gespeichert. siehe adminService -> setPassword(passwordHashingService.hashPassword("Fuu!12345")).
das ganze wird dann in passwordHashingService gehasht. dort wird auch validiert. Dies erhöht die sicherheit, da bei einem leak jediglich die hashes geleakt werden
und das einem nichts bringt, da man vom hash nicht auf das ursprüngliche passwort zurückrechnen kann. Zudem wurden passwortregeln implementiert.
es muss mindestens 8 zeichen lang sein, mindestens einen grossbuchstaben, einen kleinbuchstaben, eine zahl und ein sonderzeichen enthalten. -> passwordValidator
diese erweiterung stellt sicher, dass der user ein starkes passwort wählen muss.

## 2. Mögliche Erweiterungen:
- 2 faktor authentifizierung: wäre einiges besser als jediglich passwortregeln. diese bringen zwar etwas mehr sicherheit aber 2 faktor authentifizierung ist heutzutage eigentlich standard.

## 3. Schwierigkeiten:
Die entstandenen Schwierigkeiten sind kaum in so einer kurzen reflexion zusammenzufassen (leider). Es begann damit, dass ich den von ihnen vorgezeigten code erstmal verstehen musste,
da während dem sie ihn gezeigt haben, nicht genug zeit dazu war.

dann war der workflow etwa folgendermassen:
- etwas neues ausprobieren
- es funktioniert nicht
- flicken
- es funktioniert (juhuu)
- feststellen, dass etwas anderes nicht mehr funktioniert
- wieder flicken
- usw.

manchmal war es auch schwierig die balance zu finden zwischen AI nutzung und selber coden, da die kombi: irgendwelcher crazy AI code + spring magic
nicht sehr angenehm ist. leider aber wäre es ohne nicht möglich gewesen (für mich zumindest). Da ich aber auch viele probleme von hand gelöst habe (die AI konnte halt auch nicht alles)
war ich immer wieder dazu gezwungen den code zu verstehen und so habe ich mittlerweile einen ziemlich guten überblick.

## 4. Aufwand vs Ertrag:
Leider habe ich im betrieb noch nichts derartiges gemacht, da ich nur in projekten gearbeitet habe wo die Security bereits geregelt war, bzw sich andere darum gekümmert haben.
in diesem projekt, muss ich sagen sind dinge wie user roles und passworthashing wirklich einfach gegangen. wobei passworthashing meiner meinung nach bereits sehr wichtig ist aber
nicht direkt die sicherheit erhöht (jemand muss ja erstmal zugriff auf DB bekommen damit es etwas bringt). user roles hingegen haben bereits einen viel direkteren impact.
es sorgt meiner meinung nach für eine Übersichtliche Access Control und User Management.
CSRF tokens sind auch sehr wichtig und ein absoluter no-brainer. Es war zwar für mich sehr aufwendig, hat sich aber gelohnt. Ich bin mir aber auch sicher, dass wenn
man es ein paar mal gemacht hat, es immer einfacher wird.



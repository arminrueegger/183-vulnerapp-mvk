# 1. Sicherheitsmechanismen, die ich implementiert habe:
- Password wird jetzt gehasht mit BCrypt, nicht mehr im Klartext gespeichert.
- Session authentifizierung mit Cookie, server side mit dem formLogin von Spring Security.
- REST verbs. GET request können jetzt nur Lesen, POST erstellt, DELETE löscht. CSRF macht jetzt keinen sinn mehr
- SQL Injection wird nicht mehr aus benutzer eingaben gebaut, es gibt keine stelle mehr an der die user eingabe zu SQL query wird. und ich mach es jetzt auch mit Prepared Statments was es auch unmöglich macht Sql Injection zu machen.
- XSS: im frontend wird der blog inhalt mit textContent statt innerHtml gerendert. Damit wird der Inhalt als Text gerenderd.
- CSRF: Cookie + Token, browser schickt Session Cookie automatisch aber externe/fremde Seiten können XSRF token nicht lesen

# 2. Weitere Sinnvolle Sicherheitsmassnahmen:
- Rate Limiting: um Brute Force Angriffe zu verhindern
- Dependency Scanning um bekannte vulnarabilities in Librarys/Abhängigkeiten zu finden
- whoami endpoint gibt auch das passwort feld zurück auch wenn es gehashd ist nicht sehr sicher. Sollte ein DTO ohne das Passwort feld returnen

# 3. Schwierigkeiten und Probleme:
- DTO's machen anstatt einfach JPA eintities zurückzugeben dann hätte man auch oben das problem mit dem Passwort feld nicht.
- Tests früeher schrieben wenn man fast alle tests immer nacher implememntiert ist es sehr nervig zu machen. (und nacher alles fixen)

# 4. Aufwand und Ertrag von Sicherheitsmassnahmen bei Webapplikationen:
- Viel Ertrag für wenig aufwand: zB passwort Hashing oder CSRF schutz und Session Auth. ist fast muss und vorallem so etwas wie passwort Hashing ist nicht sehr aufwändig und ist wirtklich ein muss.
- so etwas wie Rate Limiting oder Dependency Scanning ist auch nicht sehr aufwändig aber die wahrscheinlichkeit das es relevant wird ist (meiner Meinung nach) geringer aber wenn man es braucht dann rettet es einen vor einem Angriff aber es wird wahscheinlich nicht zum einsatz kommen. (Wenn man nicht zu viele sketchy libraries installliert)
- Sachen die sich fast nicht lohnen habe ich hier nicht gross gemacht und auch geschäftlich fast nie. Gehe Security meisten eh aus dem weg wenn es geht.
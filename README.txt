GUIDA ALL’USO DEL PASSWORD MANAGER (Java)

  -----------------------------
  1. INTRODUZIONE
  -----------------------------
  Questo programma è un
  Password Manager offline
  scritto in Java. Permette di
  creare, visualizzare,
  modificare ed eliminare
  credenziali (username,
  password e note) in modo
  sicuro tramite crittografia
  AES‑256.

  La sicurezza è garantita
  da: - Una master password
  scelta dall’utente - Una
  derivazione della chiave
  tramite PBKDF2 - Un file
  crittografato chiamato
  “vault.dat”
  -----------------------------

2. COME SI AVVIA IL PROGRAMMA

1)  Compila il file Java: javac PasswordManager.java

2)  Avvia il programma: java PasswordManager

3)  Se è la prima volta, ti chiederà di impostare una master password.
    Successivamente verrà generato il file crittografato “vault.dat”.

  -----------------------------
  3. FUNZIONAMENTO DEL MENU
  PRINCIPALE
  -----------------------------
  Il programma presenta un menu
  testuale con diverse opzioni:

  1) Aggiungi voce Permette di
  creare una nuova credenziale
  composta da: - Nome
  (sito/app) - Username -
  Password (a scelta o generata
  automaticamente) - Note
  opzionali La voce viene
  salvata in modo sicuro nel
  file crittografato.

  2) Lista voci Mostra tutte le
  credenziali salvate, ognuna
  con un indice.

  3) Visualizza voce Dopo aver
  selezionato un indice, il
  programma mostra: - Nome -
  Username - Password - Note
  associate

  4) Elimina voce Permette di
  rimuovere una voce
  selezionandola tramite
  indice.

  5) Cambia master password
  Consente di cambiare la
  password principale. Tutto il
  vault viene ricrittografato
  con la nuova password.

  6) Genera password casuale
  Offre un generatore di
  password con lunghezza
  personalizzabile e
  possibilità di includere
  maiuscole, numeri e simboli.

  0) Esci Salva lo stato e
  chiude l’applicazione.
  -----------------------------

4. COME FUNZIONA LA CRITTOGRAFIA

Il programma utilizza: - PBKDF2WithHmacSHA256 per generare una chiave
sicura dalla master password - AES‑256 in modalità CBC con IV casuale -
Serializzazione Java per salvare le voci prima della crittografia

Struttura del file ‘vault.dat’: [magic] [salt] [iv] [dati_crittografati]

  -----------------------------
  5. CONSIGLI PER L’USO
  -----------------------------
  - Scegli una master password
  lunga e complessa. - Non
  condividere mai il file
  ‘vault.dat’. - Fai sempre una
  copia di backup del file. -
  Una volta dimenticata la
  master password, non esiste
  un metodo per recuperare i
  dati.

  -----------------------------

6. NOTA FINALE

Questa guida spiega l’uso e il funzionamento generale del programma.

futuri aggiornamenti:

aggiungere funzionalità o migliorare la sicurezza, ampliare il
codice con: HMAC, file JSON, interfaccia grafica, controlli backup, ecc.

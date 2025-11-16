/*
Password Manager (offline) - esempio Java in un singolo file

Caratteristiche:
- Protetto da password master (PBKDF2WithHmacSHA256)
- Crittografia AES-256 (CBC + PKCS5Padding) dei dati serializzati
- Memorizza voci (nome, username, password, note)
- Aggiungi / Elenca / Visualizza / Elimina voci
- Cambia password master
- Generatore di password
- Nessuna libreria esterna richiesta (usa funzioni integrate di Java e serializzazione Java)

Uso:
1) Compila: javac PasswordManager.java
2) Esegui:  java PasswordManager

Al primo avvio creerà un file dati 'vault.dat' e ti chiederà di impostare una password master.

Note / prossimi passi che puoi fare:
- Sostituire la serializzazione Java con JSON (Gson/Jackson) per portabilità
- Aggiungere test (JUnit)
- Aggiungere flag CLI o una GUI (JavaFX / Swing)
- Migliorare formato file/versioning e aggiungere HMAC di integrità

DISCLAIMER: Questo è un esempio educativo. Per uso in produzione, usa formati di archiviazione e librerie ben controllate, e considera protezioni aggiuntive (HSM, servizi di gestione segreti, controlli di integrità più forti).
*/

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager {
    private static final Path VAULT_PATH = Path.of("vault.dat");
    private static final String MAGIC = "PMGRv1"; // 6 bytes
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 16;
    private static final int ITERATIONS = 200_000; // regolabile
    private static final int KEY_BITS = 256;

    /* Voce e store serializzabili */
    public static class Entry implements Serializable {
        private static final long serialVersionUID = 1L;
        public String name;
        public String username;
        public String password;
        public String notes;

        public Entry(String name, String username, String password, String notes) {
            this.name = name;
            this.username = username;
            this.password = password;
            this.notes = notes;
        }

        @Override
        public String toString() {
            return String.format("%s (utente: %s)", name, username);
        }
    }

    public static class Store implements Serializable {
        private static final long serialVersionUID = 1L;
        public List<Entry> entries = new ArrayList<>();
    }

    /* Helper: deriva chiave AES da password master e salt */
    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BITS);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /* Cripta store serializzato */
    private static byte[] encrypt(Store store, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(store);
        }
        byte[] plain = bos.toByteArray();
        return cipher.doFinal(plain);
    }

    /* Decripta a store */
    private static Store decrypt(byte[] cipherText, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherText);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(plain))) {
            Object o = ois.readObject();
            return (Store) o;
        }
    }

    /* Salva file vault: header + salt + iv + ciphertext */
    private static void saveVault(byte[] salt, byte[] iv, byte[] ciphertext) throws IOException {
        try (OutputStream os = Files.newOutputStream(VAULT_PATH)) {
            os.write(MAGIC.getBytes(StandardCharsets.UTF_8));
            os.write(salt);
            os.write(iv);
            os.write(ciphertext);
        }
    }

    /* Carica vault: restituisce null se il file manca */
    private static VaultFile loadVaultFile() throws IOException {
        if (!Files.exists(VAULT_PATH)) return null;
        byte[] all = Files.readAllBytes(VAULT_PATH);
        byte[] magicBytes = Arrays.copyOfRange(all, 0, MAGIC.length());
        String magic = new String(magicBytes, StandardCharsets.UTF_8);
        if (!MAGIC.equals(magic)) throw new IOException("File vault non valido (magic non corrisponde)");
        int pos = MAGIC.length();
        byte[] salt = Arrays.copyOfRange(all, pos, pos + SALT_LEN); pos += SALT_LEN;
        byte[] iv   = Arrays.copyOfRange(all, pos, pos + IV_LEN); pos += IV_LEN;
        byte[] cipher = Arrays.copyOfRange(all, pos, all.length);
        return new VaultFile(salt, iv, cipher);
    }

    private static class VaultFile {
        byte[] salt;
        byte[] iv;
        byte[] cipher;
        VaultFile(byte[] s, byte[] i, byte[] c) { salt = s; iv = i; cipher = c; }
    }

    /* Semplice interfaccia console */
    public static void main(String[] args) throws Exception {
        Console console = System.console();
        Scanner in = new Scanner(System.in);
        if (console == null) {
            System.err.println("Console non disponibile. Esegui da un terminale. Uscita.");
            return;
        }

        VaultFile vf = loadVaultFile();
        Store store = null;
        char[] master = null;
        if (vf == null) {
            System.out.println("Nessun vault trovato — creazione di uno nuovo.");
            master = readPassword(console, "Imposta una password master: ");
            char[] confirm = readPassword(console, "Conferma password master: ");
            if (!Arrays.equals(master, confirm)) {
                System.out.println("Le password non corrispondono. Uscita.");
                return;
            }
            byte[] salt = randomBytes(SALT_LEN);
            byte[] iv = randomBytes(IV_LEN);
            SecretKey key = deriveKey(master, salt);
            store = new Store();
            byte[] cipher = encrypt(store, key, iv);
            saveVault(salt, iv, cipher);
            System.out.println("Vault creato in: " + VAULT_PATH.toAbsolutePath());
        } else {
            for (int attempts = 0; attempts < 3; attempts++) {
                master = readPassword(console, "Password master: ");
                try {
                    SecretKey key = deriveKey(master, vf.salt);
                    store = decrypt(vf.cipher, key, vf.iv);
                    break;
                } catch (Exception e) {
                    System.out.println("Password errata o vault corrotto. Tentativi rimasti: " + (2 - attempts));
                    if (attempts == 2) {
                        System.out.println("Troppi tentativi falliti. Uscita.");
                        return;
                    }
                }
            }
        }

        // ciclo principale
        boolean running = true;
        while (running) {
            System.out.println("\n--- Gestore Password ---");
            System.out.println("1) Aggiungi voce");
            System.out.println("2) Elenca voci");
            System.out.println("3) Visualizza voce");
            System.out.println("4) Elimina voce");
            System.out.println("5) Cambia password master");
            System.out.println("6) Genera password casuale");
            System.out.println("0) Esci");
            System.out.print("Scegli: ");
            String choice = in.nextLine().trim();
            switch (choice) {
                case "1": addEntry(console, in, store); save(store, master); break;
                case "2": listEntries(store); break;
                case "3": viewEntry(console, in, store); break;
                case "4": deleteEntry(in, store); save(store, master); break;
                case "5": master = changeMaster(console, store, master); break;
                case "6": System.out.println(generatePasswordInteractive(console)); break;
                case "0": running = false; save(store, master); break;
                default: System.out.println("Scelta non valida");
            }
        }
        // azzera master in memoria
        if (master != null) Arrays.fill(master, '\0');
        System.out.println("Arrivederci");
    }

    private static void addEntry(Console console, Scanner in, Store store) {
        System.out.print("Nome (sito/app): "); String name = in.nextLine().trim();
        System.out.print("Nome utente: "); String user = in.nextLine().trim();
        char[] pw = readPassword(console, "Password (lascia vuoto per generare): ");
        String password;
        if (pw.length == 0) {
            password = generatePassword(16, true, true, true);
            System.out.println("Password generata: " + password);
        } else {
            password = new String(pw);
        }
        System.out.print("Note (opzionale): "); String notes = in.nextLine().trim();
        store.entries.add(new Entry(name, user, password, notes));
        // pulisci pw
        Arrays.fill(pw, '\0');
        System.out.println("Voce aggiunta.");
    }

    private static void listEntries(Store store) {
        if (store.entries.isEmpty()) {
            System.out.println("Nessuna voce."); return;
        }
        for (int i = 0; i < store.entries.size(); i++) {
            Entry e = store.entries.get(i);
            System.out.printf("%d) %s\n", i+1, e.toString());
        }
    }

    private static void viewEntry(Console console, Scanner in, Store store) {
        listEntries(store);
        if (store.entries.isEmpty()) return;
        System.out.print("Scegli indice: ");
        String s = in.nextLine().trim();
        try {
            int idx = Integer.parseInt(s)-1;
            if (idx < 0 || idx >= store.entries.size()) { System.out.println("Indice non valido"); return; }
            Entry e = store.entries.get(idx);
            System.out.println("---");
            System.out.println("Nome: " + e.name);
            System.out.println("Nome utente: " + e.username);
            System.out.println("Password: " + e.password);
            System.out.println("Note: " + e.notes);
            System.out.println("---");
        } catch (NumberFormatException ex) { System.out.println("Numero non valido"); }
    }

    private static void deleteEntry(Scanner in, Store store) {
        listEntries(store);
        if (store.entries.isEmpty()) return;
        System.out.print("Scegli indice da eliminare: ");
        String s = in.nextLine().trim();
        try {
            int idx = Integer.parseInt(s)-1;
            if (idx < 0 || idx >= store.entries.size()) { System.out.println("Indice non valido"); return; }
            Entry e = store.entries.remove(idx);
            System.out.println("Rimosso: " + e.name);
        } catch (NumberFormatException ex) { System.out.println("Numero non valido"); }
    }

    private static char[] changeMaster(Console console, Store store, char[] oldMaster) {
        char[] current = readPassword(console, "Password master attuale: ");
        if (!Arrays.equals(current, oldMaster)) {
            System.out.println("La password master attuale non corrisponde a quella in memoria. Reinserisci la password master per ri-criptare il vault.");
            // Questo è un controllo semplice; in memoria manteniamo oldMaster. Un approccio più sicuro ri-deriva dal file.
            return oldMaster;
        }
        char[] next = readPassword(console, "Nuova password master: ");
        char[] confirm = readPassword(console, "Conferma nuova password master: ");
        if (!Arrays.equals(next, confirm)) { System.out.println("Non corrispondono. Operazione annullata."); return oldMaster; }
        try {
            byte[] salt = randomBytes(SALT_LEN);
            byte[] iv = randomBytes(IV_LEN);
            SecretKey key = deriveKey(next, salt);
            byte[] cipher = encrypt(store, key, iv);
            saveVault(salt, iv, cipher);
            Arrays.fill(oldMaster, '\0');
            System.out.println("Password master cambiata.");
            return next;
        } catch (Exception e) {
            System.out.println("Impossibile ri-criptare il vault: " + e.getMessage());
            return oldMaster;
        }
    }

    private static void save(Store store, char[] master) {
        try {
            VaultFile vf = loadVaultFile();
            byte[] salt = (vf != null) ? vf.salt : randomBytes(SALT_LEN);
            byte[] iv = randomBytes(IV_LEN);
            SecretKey key = deriveKey(master, salt);
            byte[] cipher = encrypt(store, key, iv);
            saveVault(salt, iv, cipher);
            // pulisci cipher in memoria? non facilmente possibile
        } catch (Exception e) {
            System.out.println("Impossibile salvare il vault: " + e.getMessage());
        }
    }

    private static char[] readPassword(Console console, String prompt) {
        char[] pw = console.readPassword(prompt);
        if (pw == null) return new char[0];
        return pw;
    }

    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }

    /* Generatore di password */
    private static String generatePassword(int length, boolean upper, boolean digits, boolean symbols) {
        String lower = "abcdefghijklmnopqrstuvwxyz";
        String upperS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String digitsS = "0123456789";
        String symbolsS = "!@#$%^&*()-_=+[]{};:,.<>?";
        StringBuilder pool = new StringBuilder(lower);
        if (upper) pool.append(upperS);
        if (digits) pool.append(digitsS);
        if (symbols) pool.append(symbolsS);
        SecureRandom rnd = new SecureRandom();
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < length; i++) out.append(pool.charAt(rnd.nextInt(pool.length())));
        return out.toString();
    }

    private static String generatePasswordInteractive(Console console) {
        System.out.print("Lunghezza (es. 16): ");
        String lenStr = console.readLine();
        int len = 16;
        try { len = Integer.parseInt(lenStr.trim()); } catch (Exception ignored) {}
        String upper = console.readLine("Includere lettere maiuscole? (s/N): ");
        String digits = console.readLine("Includere cifre? (s/N): ");
        String symbols = console.readLine("Includere simboli? (s/N): ");
        boolean u = upper != null && (upper.equalsIgnoreCase("s") || upper.equalsIgnoreCase("si"));
        boolean d = digits != null && (digits.equalsIgnoreCase("s") || digits.equalsIgnoreCase("si"));
        boolean s = symbols != null && (symbols.equalsIgnoreCase("s") || symbols.equalsIgnoreCase("si"));
        return generatePassword(len, u, d, s);
    }
}
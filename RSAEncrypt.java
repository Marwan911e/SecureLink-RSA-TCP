import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

/**
 * TCP client (sender). Reads a 10-character name, encrypts, sends to receiver.
 * Run last, after RSAGenKey and RSADecrypt.
 *
 * Usage: java RSAEncrypt [--single | --double] [--host localhost] [--port 54321]
 */
public class RSAEncrypt {
    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 54321;
    private static final Path NAME_FILE = Path.of("name.txt");

    public static void main(String[] args) throws Exception {
        boolean doubleMode = RSAKeyUtil.isDoubleMode(args);
        String host = parseOption(args, "--host", DEFAULT_HOST);
        int port = parsePort(args);

        // Sender A uses KRA; receiver B's public KUB is used for confidentiality
        PrivateKey senderPrivate = RSAKeyUtil.loadPrivateKey("sender");
        PublicKey receiverPublic = RSAKeyUtil.loadPublicKey("receiver");

        String plaintext = loadPlaintext();
        System.out.println("Mode: " + (doubleMode ? "double RSA" : "single RSA"));
        System.out.println("Plaintext before encryption: " + plaintext);

        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        // single -> confidentiality (E_KUB) | double -> authentication then confidentiality (E_KUB(E_KRA))
        byte[] ciphertext = doubleMode
                ? encryptDouble(plaintextBytes, senderPrivate, receiverPublic)
                : encryptSingle(plaintextBytes, receiverPublic);

        System.out.println("Ciphertext (Base64): " + RSAKeyUtil.toBase64(ciphertext));
        System.out.println("Ciphertext length: " + ciphertext.length + " bytes");

        try (Socket socket = new Socket(host, port);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            out.writeInt(ciphertext.length);
            out.write(ciphertext);
            out.flush();
            System.out.println("Sent ciphertext to " + host + ":" + port);
        }
    }

    // C = E_KUB(P) — confidentiality; only receiver B (KRB) can recover P
    private static byte[] encryptSingle(byte[] plaintext, PublicKey receiverPublic) throws Exception {
        Cipher cipher = Cipher.getInstance(RSAKeyUtil.CIPHER_PKCS1);
        cipher.init(Cipher.ENCRYPT_MODE, receiverPublic); // E_KUB
        return cipher.doFinal(plaintext);                  // C = M^e mod n
    }

    /**
     * Double RSA: PKCS#1 with sender private, then NoPadding with receiver public
     * (a full PKCS#1 block cannot be PKCS#1-encrypted again).
     * C = E_KUB(E_KRA(P)) — authentication (inner) + confidentiality (outer)
     */
    private static byte[] encryptDouble(byte[] plaintext, PrivateKey senderPrivate, PublicKey receiverPublic)
            throws Exception {
        // Inner: E_KRA(P) — authentication
        Cipher pkcs1 = Cipher.getInstance(RSAKeyUtil.CIPHER_PKCS1);
        pkcs1.init(Cipher.ENCRYPT_MODE, senderPrivate);
        byte[] step1 = pkcs1.doFinal(plaintext);

        // Outer: E_KUB(step1) — confidentiality
        Cipher noPad = Cipher.getInstance(RSAKeyUtil.CIPHER_NOPAD);
        noPad.init(Cipher.ENCRYPT_MODE, receiverPublic);
        return noPad.doFinal(step1);
    }

    private static String loadPlaintext() throws IOException {
        if (!Files.exists(NAME_FILE)) {
            throw new IOException("Missing " + NAME_FILE + ". Create a 10-character name file.");
        }
        String raw = Files.readString(NAME_FILE, StandardCharsets.UTF_8).trim();
        if (raw.length() > 10) {
            raw = raw.substring(0, 10);
            System.out.println("Note: name trimmed to 10 characters.");
        } else if (raw.length() < 10) {
            raw = String.format("%-10s", raw);
            System.out.println("Note: name padded with spaces to 10 characters.");
        }
        return raw;
    }

    private static String parseOption(String[] args, String flag, String defaultValue) {
        for (int i = 0; i < args.length - 1; i++) {
            if (flag.equals(args[i])) {
                return args[i + 1];
            }
        }
        return defaultValue;
    }

    private static int parsePort(String[] args) {
        String portStr = parseOption(args, "--port", String.valueOf(DEFAULT_PORT));
        return Integer.parseInt(portStr);
    }
}

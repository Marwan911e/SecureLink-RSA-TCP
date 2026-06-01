import java.io.DataInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

/**
 * TCP server (receiver). Listens for ciphertext, decrypts, prints results.
 * Run second, after RSAGenKey and before RSAEncrypt.
 *
 * Usage: java RSADecrypt [--single | --double]
 */
public class RSADecrypt {

    private static final int DEFAULT_PORT = 54321;

    public static void main(String[] args) throws Exception {
        boolean doubleMode = RSAKeyUtil.isDoubleMode(args);
        int port = parsePort(args);

        // Receiver B uses KRB; sender A's public KUA verifies the inner authentication layer
        PrivateKey receiverPrivate = RSAKeyUtil.loadPrivateKey("receiver");
        PublicKey senderPublic = RSAKeyUtil.loadPublicKey("sender");

        System.out.println("Mode: " + (doubleMode ? "double RSA" : "single RSA"));
        System.out.println("Listening on port " + port + " ...");

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            try (Socket client = serverSocket.accept();
                 DataInputStream in = new DataInputStream(client.getInputStream())) {

                System.out.println("Connection from " + client.getInetAddress());

                byte[] ciphertext = readFramed(in);
                System.out.println("Ciphertext (Base64): " + RSAKeyUtil.toBase64(ciphertext));
                System.out.println("Ciphertext length: " + ciphertext.length + " bytes");

                // single -> D_KRB(C) | double -> D_KUA(D_KRB(C))
                byte[] plaintextBytes = doubleMode
                        ? decryptDouble(ciphertext, receiverPrivate, senderPublic)
                        : decryptSingle(ciphertext, receiverPrivate);

                String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
                System.out.println("Plaintext after decryption: " + plaintext);
            }
        }
    }

    // P = D_KRB(C) — reverse confidentiality; only B's private key works
    private static byte[] decryptSingle(byte[] ciphertext, PrivateKey receiverPrivate) throws Exception {
        Cipher cipher = Cipher.getInstance(RSAKeyUtil.CIPHER_PKCS1);
        cipher.init(Cipher.DECRYPT_MODE, receiverPrivate); // D_KRB
        return cipher.doFinal(ciphertext);                  // M = C^d mod n
    }

    /**
     * Inverse of encryptDouble: NoPadding with receiver private, then PKCS#1 with sender public.
     * P = D_KUA(D_KRB(C)) — reverse outer confidentiality, then inner authentication
     */
    private static byte[] decryptDouble(byte[] ciphertext, PrivateKey receiverPrivate, PublicKey senderPublic)
            throws Exception {
        // Step 1: D_KRB(C) — undo outer E_KUB
        Cipher noPad = Cipher.getInstance(RSAKeyUtil.CIPHER_NOPAD);
        noPad.init(Cipher.DECRYPT_MODE, receiverPrivate);
        byte[] step1 = noPad.doFinal(ciphertext);

        // Step 2: D_KUA(step1) — undo inner E_KRA
        Cipher pkcs1 = Cipher.getInstance(RSAKeyUtil.CIPHER_PKCS1);
        pkcs1.init(Cipher.DECRYPT_MODE, senderPublic);
        return pkcs1.doFinal(step1);
    }

    private static byte[] readFramed(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length <= 0 || length > 1_000_000) {
            throw new IOException("Invalid ciphertext length: " + length);
        }
        byte[] data = new byte[length];
        in.readFully(data);
        return data;
    }

    private static int parsePort(String[] args) {
        for (int i = 0; i < args.length - 1; i++) {
            if ("--port".equals(args[i])) {
                return Integer.parseInt(args[i + 1]);
            }
        }
        return DEFAULT_PORT;
    }
}

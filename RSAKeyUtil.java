import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Shared RSA key I/O and cipher helpers for RSAGenKey, RSAEncrypt, RSADecrypt.
 */
public final class RSAKeyUtil {

    public static final String CIPHER_PKCS1 = "RSA/ECB/PKCS1Padding";
    public static final String CIPHER_NOPAD = "RSA/ECB/NoPadding";
    public static final int KEY_SIZE = 2048;
    public static final Path KEYS_DIR = Path.of("keys");

    private RSAKeyUtil() {
    }

    // RSA steps 1-4: pick p,q -> n=p*q -> choose e -> compute d where e*d mod phi(n)=1
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_SIZE);
        return generator.generateKeyPair();
    }

    // Save public KU={e,n} and private KR={d,n} to disk (KUA/KRA or KUB/KRB)
    public static void saveKeyPair(KeyPair pair, String prefix) throws IOException {
        Files.createDirectories(KEYS_DIR);
        writeKey(KEYS_DIR.resolve(prefix + "_private.key"), pair.getPrivate().getEncoded());
        writeKey(KEYS_DIR.resolve(prefix + "_public.key"), pair.getPublic().getEncoded());
    }

    private static void writeKey(Path path, byte[] encoded) throws IOException {
        String base64 = Base64.getEncoder().encodeToString(encoded);
        Files.writeString(path, base64, StandardCharsets.UTF_8);
    }

    // Load KR (KRA or KRB) — the private key {d,n}
    public static PrivateKey loadPrivateKey(String prefix) throws Exception {
        byte[] encoded = readKeyBytes(KEYS_DIR.resolve(prefix + "_private.key"));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    // Load KU (KUA or KUB) — the public key {e,n}
    public static PublicKey loadPublicKey(String prefix) throws Exception {
        byte[] encoded = readKeyBytes(KEYS_DIR.resolve(prefix + "_public.key"));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static byte[] readKeyBytes(Path path) throws IOException {
        String base64 = Files.readString(path, StandardCharsets.UTF_8).trim();
        return Base64.getDecoder().decode(base64);
    }

    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    // --single = E_KUB(P) only | --double = E_KUB(E_KRA(P))
    public static boolean isDoubleMode(String[] args) {
        if (args.length == 0) {
            return false;
        }
        for (String arg : args) {
            if ("--double".equalsIgnoreCase(arg)) {
                return true;
            }
            if ("--single".equalsIgnoreCase(arg)) {
                return false;
            }
        }
        return false;
    }
}

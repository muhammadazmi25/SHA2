import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SHA {
    // SHA-256/224 constants
    private static final int[] K256 = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // SHA-512/384 constants
    private static final long[] K512 = {
            0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
            0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
            0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
            0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
            0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
            0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
            0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
            0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
            0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
            0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
            0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
            0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
            0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
            0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
            0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
            0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
            0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
            0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
            0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
            0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };

    // Initial hash values
    private static final int[] H256 = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    private static final int[] H224 = {
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    };

    private static final long[] H384 = {
            0xcbbb9d5dc1059ed8L, 0x629a292a367cd507L, 0x9159015a3070dd17L, 0x152fecd8f70e5939L,
            0x67332667ffc00b31L, 0x8eb44a8768581511L, 0xdb0c2e0d64f98fa7L, 0x47b5481dbefa4fa4L
    };

    private static final long[] H512 = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    // Utility functions for 32-bit operations
    private static int rightRotate(int x, int n) {
        return (x >>> n) | (x << (32 - n));
    }

    private static int choose(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    private static int majority(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private static int sigma0(int x) {
        return rightRotate(x, 2) ^ rightRotate(x, 13) ^ rightRotate(x, 22);
    }

    private static int sigma1(int x) {
        return rightRotate(x, 6) ^ rightRotate(x, 11) ^ rightRotate(x, 25);
    }

    private static int gamma0(int x) {
        return rightRotate(x, 7) ^ rightRotate(x, 18) ^ (x >>> 3);
    }

    private static int gamma1(int x) {
        return rightRotate(x, 17) ^ rightRotate(x, 19) ^ (x >>> 10);
    }

    // Utility functions for 64-bit operations
    private static long rightRotate64(long x, int n) {
        return (x >>> n) | (x << (64 - n));
    }

    private static long choose64(long x, long y, long z) {
        return (x & y) ^ (~x & z);
    }

    private static long majority64(long x, long y, long z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private static long sigma0_64(long x) {
        return rightRotate64(x, 28) ^ rightRotate64(x, 34) ^ rightRotate64(x, 39);
    }

    private static long sigma1_64(long x) {
        return rightRotate64(x, 14) ^ rightRotate64(x, 18) ^ rightRotate64(x, 41);
    }

    private static long gamma0_64(long x) {
        return rightRotate64(x, 1) ^ rightRotate64(x, 8) ^ (x >>> 7);
    }

    private static long gamma1_64(long x) {
        return rightRotate64(x, 19) ^ rightRotate64(x, 61) ^ (x >>> 6);
    }

    // SHA-256 implementation
    private static byte[] sha256(byte[] message) {
        return sha256Internal(message, H256, 32);
    }

    // SHA-224 implementation
    private static byte[] sha224(byte[] message) {
        return sha256Internal(message, H224, 28);
    }

    private static byte[] sha256Internal(byte[] message, int[] initH, int digestLength) {
        int[] hash = Arrays.copyOf(initH, initH.length);

        // Padding
        int originalLength = message.length * 8;
        int paddedLength = ((message.length + 8) / 64 + 1) * 64;
        byte[] paddedMessage = Arrays.copyOf(message, paddedLength);
        paddedMessage[message.length] = (byte) 0x80;

        ByteBuffer buffer = ByteBuffer.wrap(paddedMessage);
        buffer.position(paddedLength - 8);
        buffer.putLong(originalLength);

        // Process each 512-bit chunk
        for (int i = 0; i < paddedMessage.length; i += 64) {
            int[] w = new int[64];
            for (int t = 0; t < 16; t++) {
                w[t] = buffer.getInt(i + t * 4);
            }
            for (int t = 16; t < 64; t++) {
                w[t] = gamma1(w[t - 2]) + w[t - 7] + gamma0(w[t - 15]) + w[t - 16];
            }

            int a = hash[0], b = hash[1], c = hash[2], d = hash[3];
            int e = hash[4], f = hash[5], g = hash[6], h = hash[7];

            for (int t = 0; t < 64; t++) {
                int t1 = h + sigma1(e) + choose(e, f, g) + K256[t] + w[t];
                int t2 = sigma0(a) + majority(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            hash[0] += a;
            hash[1] += b;
            hash[2] += c;
            hash[3] += d;
            hash[4] += e;
            hash[5] += f;
            hash[6] += g;
            hash[7] += h;
        }

        ByteBuffer result = ByteBuffer.allocate(digestLength);
        for (int i = 0; i < digestLength / 4; i++) {
            result.putInt(hash[i]);
        }

        return result.array();
    }

    // SHA-512 implementation
    private static byte[] sha512(byte[] message) {
        return sha512Internal(message, H512, 64);
    }

    // SHA-384 implementation
    private static byte[] sha384(byte[] message) {
        return sha512Internal(message, H384, 48);
    }

    private static byte[] sha512Internal(byte[] message, long[] initH, int digestLength) {
        long[] hash = Arrays.copyOf(initH, initH.length);

        // Padding
        int originalLength = message.length * 8;
        int paddedLength = ((message.length + 16) / 128 + 1) * 128;
        byte[] paddedMessage = Arrays.copyOf(message, paddedLength);
        paddedMessage[message.length] = (byte) 0x80;

        ByteBuffer buffer = ByteBuffer.wrap(paddedMessage);
        buffer.position(paddedLength - 16);
        buffer.putLong(0); // High-order 64 bits of length (always 0 for now)
        buffer.putLong(originalLength);

        // Process each 1024-bit chunk
        for (int i = 0; i < paddedMessage.length; i += 128) {
            long[] w = new long[80];
            for (int t = 0; t < 16; t++) {
                w[t] = buffer.getLong(i + t * 8);
            }
            for (int t = 16; t < 80; t++) {
                w[t] = gamma1_64(w[t - 2]) + w[t - 7] + gamma0_64(w[t - 15]) + w[t - 16];
            }

            long a = hash[0], b = hash[1], c = hash[2], d = hash[3];
            long e = hash[4], f = hash[5], g = hash[6], h = hash[7];

            for (int t = 0; t < 80; t++) {
                long t1 = h + sigma1_64(e) + choose64(e, f, g) + K512[t] + w[t];
                long t2 = sigma0_64(a) + majority64(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            hash[0] += a;
            hash[1] += b;
            hash[2] += c;
            hash[3] += d;
            hash[4] += e;
            hash[5] += f;
            hash[6] += g;
            hash[7] += h;
        }

        ByteBuffer result = ByteBuffer.allocate(digestLength);
        for (int i = 0; i < digestLength / 8; i++) {
            result.putLong(hash[i]);
        }

        return result.array();
    }

    // Public interface methods
    public static String sha224String(String input) {
        byte[] hash = sha224(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    public static String sha256String(String input) {
        byte[] hash = sha256(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    public static String sha384String(String input) {
        byte[] hash = sha384(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    public static String sha512String(String input) {
        byte[] hash = sha512(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public static void main(String[] args) {
        System.out.print("Masukkan input: ");
        String input = new java.util.Scanner(System.in).nextLine();
        
        System.out.println("SHA-224: " + sha224String(input));
        System.out.println("SHA-256: " + sha256String(input));
        System.out.println("SHA-384: " + sha384String(input));
        System.out.println("SHA-512: " + sha512String(input));
    }
}
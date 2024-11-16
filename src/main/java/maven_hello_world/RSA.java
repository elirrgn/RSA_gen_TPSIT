package maven_hello_world;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
import java.util.StringTokenizer;

public class RSA {
	private static final Logger logger = LogManager.getLogger(RSA.class);
	static final int bitLength = 1024; 
	static final String token = ";"; // Token used as separation between chars encrypted

	public static void main(String[] args) {
		// Set maximum log level to INFO
		Configurator.setAllLevels(LogManager.getRootLogger().getName(), Level.INFO);
		Random rand = new Random();
		Scanner scn = new Scanner(System.in);
		BigInteger n, d, e;

		do {
			BigInteger p = BigInteger.probablePrime(bitLength, rand);
			BigInteger q = BigInteger.probablePrime(bitLength, rand);
	
			while(p.compareTo(q) == 0) {
				q = BigInteger.probablePrime(bitLength, rand);
			}
	
			n = p.multiply(q);
			BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
	
			e = generateCoPrime(phi);
	
			d = e.modInverse(phi);
		} while(!check(e, d, n)); // Check if probablePrime worked

		logger.info("Inserisci il messaggio da criptare: ");
		String msg = scn.nextLine();
		logger.info("Messaggio da criptare: " + msg);

		String c = encrypt(msg, e, n);
		logger.info("Encrypted = "+ c);
		logger.info("Decrypted = "+ decrypt(c, d, n));
		scn.close();
	}

	/**
	 * Generates a coprime number of n
	 * 
	 * @param n number which needs a coprime
	 * @return the coprime number
	 */
	public static BigInteger generateCoPrime(BigInteger n) {
		Random rand = new Random();
		BigInteger coprime = BigInteger.probablePrime(bitLength, rand);
		while(coprime.compareTo(n)>0) {
			coprime = BigInteger.probablePrime(bitLength, rand);
		}
		return coprime;
	}

	/**
	 * Checks if the keys generated work
	 * 
	 * @param pubExp public exponent
	 * @param privExp private exponent
	 * @param n module
	 * @return true if the keys work
	 */
	public static boolean check(BigInteger pubExp, BigInteger privExp, BigInteger n) {
		String sampleMsg = "ciao";
		return decrypt(encrypt(sampleMsg, pubExp, n), privExp, n).equals(sampleMsg);
	}

	/**
	 * Encrypts the message using the key given
	 * 
	 * @param msg message to enccrypt
	 * @param pubExp public exponent
	 * @param n module
	 * @return the encrypted message
	 */
	public static String encrypt(String msg, BigInteger pubExp, BigInteger n) {
		char[] charMsg = msg.toCharArray();
		StringBuilder c = new StringBuilder();

		for(char ch: charMsg) {
			BigInteger crypt = BigInteger.valueOf(ch).modPow(pubExp, n);
			c.append(crypt.toString());
			c.append(token);
		}

		return c.toString();
	}

	/**
	 * Decrypts the message using the key given
	 * 
	 * @param c message to encrypt
	 * @param privExp private exponent
	 * @param n module
	 * @return the decrypted message
	 */
	public static String decrypt(String c, BigInteger privExp, BigInteger n) {
		StringTokenizer str = new StringTokenizer(c, token);
		StringBuilder dec =  new StringBuilder();

		while(str.hasMoreTokens()) {
			BigInteger i = new BigInteger(str.nextToken());
			dec.append((char) i.modPow(privExp, n).longValueExact());
		}

		return dec.toString();
	}
}

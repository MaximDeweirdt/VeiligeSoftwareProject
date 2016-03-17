import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Scanner;

public class WinkelMain {

	private static Winkel winkel;
	private static final char [] KEYSTOREPASWOORD = "kiwikiwi".toCharArray();
	
	private static final Scanner SCANNER = new Scanner(System.in);
	
	private static final String ALIENWARE_NAME = "Alienware";
	private static final String COLRUYT_NAME = "Colruyt";
	private static final String DELHAIZE_NAME = "Delhaize";
	private static final String RAZOR_NAME = "Razor";
	
	/**
	 * @param args
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws KeyStoreException
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException,
			IOException, KeyStoreException {


		System.out.println("Geef het nummer van de winkel.");
		System.out.println("Alienware\t1\nColruyt    \t2\nDelhaize\t3\nRazor      \t4");

		// Inlezen van het winkelnummer
		// Dit blijft gebeuren dat het winkelnummer een aanvaardbaar nummer is
		// (nummer tussen 1-4).
		int winkelnummer = Integer.parseInt(SCANNER.nextLine());
		while (winkelnummer <= 0 || winkelnummer > 4) {
			System.err.println("Het ingegeven winkelnummer is niet correct");
			winkelnummer = Integer.parseInt(SCANNER.nextLine());
		}

		// Een juist winkel object maken op basis van het ingelezen winkelnummer.
		// Default wordt Alienware gemaakt.
		
		switch (winkelnummer) {
		case 1:
			winkel = new Winkel(ALIENWARE_NAME);
			break;
		case 2:
			winkel = new Winkel(COLRUYT_NAME);
			break;
		case 3:
			winkel = new Winkel(DELHAIZE_NAME);
			break;
		case 4:
			winkel = new Winkel(RAZOR_NAME);
			break;
		default:
			System.err.println("Er ging iets mis bij het laden van de keystores: " + WinkelMain.class);
			System.err.println("De keystore van de winkel Alienware wordt default ingeladen. FEELSBADMAN");
			winkel = new Winkel(ALIENWARE_NAME);
			break;
		}
		
		winkel.startGUI();
		

	}

}

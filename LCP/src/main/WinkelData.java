package main;

public class WinkelData {
	
	private String naam;
	private Certificate cert;
	private boolean legit = true;
	
	public WinkelData(){}

	public WinkelData(Certificate cert, String naam) {
		super();
		this.cert = cert;
		this.setNaam(naam);
	}

	public Certificate getCertificate() {
		return cert;
	}

	public void setCertificate(Certificate cert) {
		this.cert = cert;
	}

	public boolean isLegit() {
		return legit;
	}

	public void setLegit(boolean legit) {
		this.legit = legit;
	}

	public String getNaam() {
		return naam;
	}

	public void setNaam(String naam) {
		this.naam = naam;
	}
	
	public void revokeCertificate() {
		legit = false;
	}
}

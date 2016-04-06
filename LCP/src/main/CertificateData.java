package main;

import java.util.ArrayList;
import java.util.List;

public class CertificateData {
	private boolean isValid;
	private List<byte[]> transactionBytesList;
	private byte[] currentTransactions;
	private int currentTransactionNumber;
	public CertificateData(){
		setTransactionBytesList(new ArrayList<>());
		setValid(true);
		currentTransactions = new byte[160];
		currentTransactionNumber = 0;
	}


	public boolean isValid() {
		return isValid;
	}


	public void setValid(boolean isValid) {
		this.isValid = isValid;
	}


	public List<byte[]> getTransactionBytesList() {
		return transactionBytesList;
	}


	public void setTransactionBytesList(List<byte[]> transactionBytesList) {
		this.transactionBytesList = transactionBytesList;
	}


	public void addData(byte[] input) {
		int currentIndex = currentTransactionNumber*8;
		
		for(int i = 0; i<8;i++){
			
			currentTransactions[currentIndex + i] = input[i];
			
		}
		
		currentTransactionNumber++;
		
	}
	
	public boolean checkLog(byte[] input){
		int i = 0;
		boolean same = true;
		while(same && i< 160){
			if(currentTransactions[i] != input[i])same = false;
			i++;
		}
		return same;
	}


	public void setRenewed() {
		transactionBytesList.add(currentTransactions);
		currentTransactions = new byte[160];
		currentTransactionNumber = 0;
		
	}
}

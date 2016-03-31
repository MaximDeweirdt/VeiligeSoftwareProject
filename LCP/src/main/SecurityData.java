package main;

public class SecurityData {

	public static byte[] publicKey = new byte[]{
			(byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, 
			(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, 
			(byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x03, 
			(byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0xa9, (byte) 0xfe, (byte) 0x35, 
			(byte) 0x45, (byte) 0xf0, (byte) 0xaf, (byte) 0x79, (byte) 0x60, (byte) 0x8f, 
			(byte) 0xd5, (byte) 0x79, (byte) 0x09, (byte) 0xcb, (byte) 0x32, (byte) 0x9b, 
			(byte) 0x77, (byte) 0xde, (byte) 0x96, (byte) 0x8a, (byte) 0x9c, (byte) 0x2e, 
			(byte) 0x3f, (byte) 0x3c, (byte) 0x63, (byte) 0x8d, (byte) 0xc4, (byte) 0x36, 
			(byte) 0x94, (byte) 0x3e, (byte) 0x62, (byte) 0x1c, (byte) 0x95, (byte) 0xb3, 
			(byte) 0xa0, (byte) 0x4b, (byte) 0x3b, (byte) 0x90, (byte) 0xab, (byte) 0x0b, 
			(byte) 0xdf, (byte) 0x14, (byte) 0x19, (byte) 0xba, (byte) 0x0a, (byte) 0xed, 
			(byte) 0x4d, (byte) 0x90, (byte) 0x2c
		};
		
		public static byte[] publicKeyParameterQ = new byte[]{
				(byte) 0x04, (byte) 0xa9, (byte) 0xfe, (byte) 0x35, (byte) 0x45, (byte) 0xf0, 
				(byte) 0xaf, (byte) 0x79, (byte) 0x60, (byte) 0x8f, (byte) 0xd5, (byte) 0x79, 
				(byte) 0x09, (byte) 0xcb, (byte) 0x32, (byte) 0x9b, (byte) 0x77, (byte) 0xde, 
				(byte) 0x96, (byte) 0x8a, (byte) 0x9c, (byte) 0x2e, (byte) 0x3f, (byte) 0x3c, 
				(byte) 0x63, (byte) 0x8d, (byte) 0xc4, (byte) 0x36, (byte) 0x94, (byte) 0x3e, 
				(byte) 0x62, (byte) 0x1c, (byte) 0x95, (byte) 0xb3, (byte) 0xa0, (byte) 0x4b, 
				(byte) 0x3b, (byte) 0x90, (byte) 0xab, (byte) 0x0b, (byte) 0xdf, (byte) 0x14, 
				(byte) 0x19, (byte) 0xba, (byte) 0x0a, (byte) 0xed, (byte) 0x4d, (byte) 0x90, 
				(byte) 0x2c
		};
		
		public static byte[] privateKey = new byte[]{
			(byte) 0x30, (byte) 0x7b, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30, 
			(byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, 
			(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, 
			(byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x61, (byte) 0x30, (byte) 0x5f, 
			(byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x18, (byte) 0x53, 
			(byte) 0xad, (byte) 0x00, (byte) 0x6a, (byte) 0xaf, (byte) 0xfd, (byte) 0xca, 
			(byte) 0x87, (byte) 0xb9, (byte) 0x58, (byte) 0xf2, (byte) 0x6e, (byte) 0x65, 
			(byte) 0x87, (byte) 0x1d, (byte) 0xbc, (byte) 0xb0, (byte) 0xe6, (byte) 0x4a, 
			(byte) 0xbe, (byte) 0xb2, (byte) 0x58, (byte) 0x69, (byte) 0x45, (byte) 0xa0, 
			(byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0xa1, 
			(byte) 0x34, (byte) 0x03, (byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0xa9, 
			(byte) 0xfe, (byte) 0x35, (byte) 0x45, (byte) 0xf0, (byte) 0xaf, (byte) 0x79, 
			(byte) 0x60, (byte) 0x8f, (byte) 0xd5, (byte) 0x79, (byte) 0x09, (byte) 0xcb, 
			(byte) 0x32, (byte) 0x9b, (byte) 0x77, (byte) 0xde, (byte) 0x96, (byte) 0x8a, 
			(byte) 0x9c, (byte) 0x2e, (byte) 0x3f, (byte) 0x3c, (byte) 0x63, (byte) 0x8d, 
			(byte) 0xc4, (byte) 0x36, (byte) 0x94, (byte) 0x3e, (byte) 0x62, (byte) 0x1c, 
			(byte) 0x95, (byte) 0xb3, (byte) 0xa0, (byte) 0x4b, (byte) 0x3b, (byte) 0x90, 
			(byte) 0xab, (byte) 0x0b, (byte) 0xdf, (byte) 0x14, (byte) 0x19, (byte) 0xba, 
			(byte) 0x0a, (byte) 0xed, (byte) 0x4d, (byte) 0x90, (byte) 0x2c
		};
		
		public static byte[] privateKeyParameterD = new byte[]{
			(byte) 0x53, (byte) 0xad, (byte) 0x00, (byte) 0x6a, (byte) 0xaf, (byte) 0xfd, 
			(byte) 0xca, (byte) 0x87, (byte) 0xb9, (byte) 0x58, (byte) 0xf2, (byte) 0x6e, 
			(byte) 0x65, (byte) 0x87, (byte) 0x1d, (byte) 0xbc, (byte) 0xb0, (byte) 0xe6, 
			(byte) 0x4a, (byte) 0xbe, (byte) 0xb2, (byte) 0x58, (byte) 0x69, (byte) 0x45
		};
}

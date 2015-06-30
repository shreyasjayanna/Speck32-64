/*
 * DecryptFile.java
 * Date: 07-10-2014
 * v2.0
 * Author: Shreyas Jayanna
 */

// import statements
import edu.rit.util.Hex;
import edu.rit.util.Packing;
import java.io.*;

/**
 * class DecryptFile
 * This class implements the decryption algorithm of SPECK32/64.
 * The input is read from a file and the plaintext is written to another file.
 */
public class DecryptFile {

    short[] subkeys;    // subkeys for each round. Generated from key scheduling
    short[] l;          // Temproray array used in key scheduling.

    /**
     * DecryptFile
     * Constructor
     */
    DecryptFile() {
        subkeys = new short[22];
        l = new short[24];
    }

    /**
     * setKey method.
     * This method sets the initial round key from the original key by packing the first 2 bytes.
     * @param key The original key
     */
    public void setKey(byte[] key) {
        subkeys[0] = Packing.packShortBigEndian(key, 6);
        l[0] = Packing.packShortBigEndian(key, 4);
        l[1] = Packing.packShortBigEndian(key, 2);
        l[2] = Packing.packShortBigEndian(key, 0);
    }

    /**
     * keySchedule method.
     * This method runs the keySchedule algorithm. It generates the subkeys for each round of encryption.
     */
    public void keySchedule() {
        int m = 4;
        for(int i = 0; i < 21; ++i) {
            int temp1, temp2, temp3;
            temp1 = subkeys[i] & 65535;
            temp2 = l[i] & 65535;

            l[i+m-1] = (short) ((temp1 + ((temp2 >>> 7) | (temp2 << (16-7)))) ^ i);
            temp3 = l[i+m-1] & 65535;

            subkeys[i+1] = (short) ((short)((temp1 << 2) | (temp1 >>> (16-2))) ^ temp3);
        }
    }

    /**
     * This method decrypts the given ciphertext.
     * @param ciphertext The ciphertext
     */
    public void decrypt(byte[] ciphertext) {
        short p1 = Packing.packShortBigEndian(ciphertext,0);
        short p2 = Packing.packShortBigEndian(ciphertext,2);

        int temp1 = p1 & 0xFFFF;
        int temp2 = p2 & 0xFFFF;

        int temp3;

        for(int i = 21; i > -1; --i) {
            temp3 = subkeys[i] & 0xFFFF;

            p2 = (short) ((((temp1 ^ temp2) & 0xFFFF) >>> 2) | (((temp1 ^ temp2) & 0xFFFF) << (16-2)));
            temp2 = p2 & 0xFFFF;

            int temp4 = (((temp1 ^ temp3) & 0xFFFF) - temp2) & 0xFFFF;
            p1 = (short) ((temp4 << 7) | (temp4 >>> (16-7)));
            temp1 = p1 & 0xFFFF;

            //    System.out.printf("%s%s%n", Hex.toString(p1), Hex.toString(p2));
        }

        Packing.unpackShortBigEndian(p1,ciphertext,0);
        Packing.unpackShortBigEndian(p2,ciphertext,2);
    }

    /**
     * main
     * The main method
     * @param args Command line arguments
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        if(args.length!=3)
            System.out.println("Not correct usage");

        File ptfile = new File(args[1]);
        File ctfile = new File(args[2]);
        byte[] key = Hex.toByteArray(args[0]);

        DecryptFile ef = new DecryptFile();
        ef.setKey(key);
        ef.keySchedule();

        FileInputStream in = new FileInputStream(ptfile);
        FileOutputStream out = new FileOutputStream(ctfile);

        byte[] data = new byte[4];
        byte[] ciphertext;
        int b;
        int count = 0;
        while(((b=in.read())!=-1)) {
            data[count++] = (byte) b;
            if(count == 4) {
                count = 0;
                ciphertext = data.clone();
                ef.decrypt(ciphertext);
                out.write(ciphertext);
            }
        }
	in.close();
	out.close();


	// Remove padding by checking the last bytes of the plaintext, one byte at a time.
	RandomAccessFile raf = new RandomAccessFile(ctfile,"rw");

	raf.seek(ctfile.length()-1);

	while(raf.readByte() == (byte) 0x00) {
	    raf.setLength(raf.length()-1);
	    raf.seek(raf.length()-1);
	}

	raf.seek(raf.length()-1);

	if(raf.readByte() == (byte) 0x80) {
	    raf.setLength(raf.length()-1);
	}
	
	raf.close();

    }
}

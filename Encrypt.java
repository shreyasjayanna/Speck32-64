/*
 * Encrypt.java
 * Date: 07-10-2014
 * v2.0
 * Author: Shreyas Jayanna
 */

// Import statements
import edu.rit.util.Hex;
import edu.rit.util.Packing;

/**
 * Class Encrypt
 * This class defines the functionality to encrypt a plaintext as per SPECK32/64.
 */
public class Encrypt {

    short[] subkeys;
    short[] l;

    /**
     * EncryptFile
     * Constructor
     */
    Encrypt() {
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
     * encrypt method.
     * This method encrypts the given plaintext.
     * @param ciphertext The plaintext. It will be replaced with the ciphertext.
     */
    public void encrypt(byte[] ciphertext) {
        short p1 = Packing.packShortBigEndian(ciphertext,0);
        short p2 = Packing.packShortBigEndian(ciphertext,2);

        int temp1 = p1 & 65535;
        int temp2 = p2 & 65535;

        int temp3;

        for(int i = 0; i < 22; ++i) {
            temp3 = subkeys[i] & 65535;
            p1 = (short) ((((temp1 >>> 7) | (temp1 << (16-7))) + temp2) ^ temp3);
            temp1  = p1 & 65535;
            p2 = (short) (((temp2 << 2) | (temp2 >>> (16-2))) ^ temp1);
            temp2 = p2 & 65535;
        }

        Packing.unpackShortBigEndian(p1,ciphertext,0);
        Packing.unpackShortBigEndian(p2,ciphertext,2);
    }

    /**
     * main
     * The main method
     * @param args Command line arguments
     */
    public static void main(String[] args) {

        if(args.length != 2) {
            System.out.println("Arguments must be 16 hexadecimal key and 8 hexadecimal plaintext.");
            System.exit(1);
        }
        else if(args[0].length() != 16){
            System.out.println("Key must be 16 hexadecimal digits.");
            System.exit(1);
        }
        else if(args[1].length() != 8) {
            System.out.println("Plaintext must be 8 hexadecimal digits.");
            System.exit(1);
        } else {

            Encrypt e = new Encrypt();

            byte[] plaintext = Hex.toByteArray(args[1]);
            byte[] key = Hex.toByteArray(args[0]);

            e.setKey(key);
            e.keySchedule();

            byte[] ciphertext = plaintext.clone();

            e.encrypt(ciphertext);

            System.out.printf("%s%n", Hex.toString(ciphertext));
        }
    }
}

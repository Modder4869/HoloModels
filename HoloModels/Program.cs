using System;
using System.IO;
using static Utils.Rijndael;

class Program
{
    private static byte[]? iv;

    static void Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.WriteLine("Usage: HoloModels.exe <input_folder> <output_folder>");
            return;
        }

        string inputFolder = args[0];
        string outputFolder = args[1];

        byte[] key = new byte[] { 145, 153, 81, 152, 6, 193, 94, 191, 35, 38, 33, 254, 47, 248, 64, 46, 119, 119, 58, 136, 217, 184, 28, 35, 62, 11, 204, 188, 149, 49, 129, 181 };
        foreach (string encryptedFilePath in Directory.GetFiles(inputFolder))
        {
            string decryptedFilePath = Path.Combine(outputFolder, Path.GetFileNameWithoutExtension(encryptedFilePath));
            Directory.CreateDirectory(outputFolder);
            byte[] encryptedData;
            using (FileStream encryptedFileStream = new FileStream(encryptedFilePath, FileMode.Open, FileAccess.Read))
            {
                iv = new byte[32];
                encryptedFileStream.Read(iv, 0, iv.Length);
                encryptedFileStream.Seek(0, SeekOrigin.Begin);
                encryptedData = new byte[encryptedFileStream.Length];
                encryptedFileStream.Read(encryptedData, 0, encryptedData.Length);
            }

            try
            {
                byte[] decryptedData = DecryptData(encryptedData, key, iv, BlockSize.Block256, KeySize.Key256, EncryptionMode.ModeCBC);

                // Check if the decrypted data is not empty before writing it
                if (decryptedData.Length > 32)
                {
                    File.WriteAllBytes(decryptedFilePath, decryptedData[32..]);
                    Console.WriteLine($"Decryption completed for {Path.GetFileName(encryptedFilePath)}. Decrypted data saved in: {decryptedFilePath}");
                }
                else
                {
                    Console.WriteLine($"Decryption failed for {Path.GetFileName(encryptedFilePath)}. Decrypted data is empty.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during decryption for {Path.GetFileName(encryptedFilePath)}: {ex.Message}");
            }
        }
    }
}
